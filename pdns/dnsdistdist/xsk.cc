/*
 * This file is part of PowerDNS or dnsdist.
 * Copyright -- PowerDNS.COM B.V. and its contributors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * In addition, for the avoidance of any doubt, permission is granted to
 * link this program with OpenSSL and to (re)distribute the binaries
 * produced as the result of such linking.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#include "dolog.hh"
#include "gettime.hh"
#include "iputils.hh"
#include "xsk.hh"

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <linux/if_ether.h>
#include <linux/if_xdp.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdexcept>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <vector>
#include <net/if.h>
inline constexpr bool XskSocket::is_pow_of_two(uint32_t value) noexcept
{
  return value != 0 && (value & (value - 1)) == 0;
}
inline int XskSocket::firstTimeout()
{
  if (waitForDelay.empty()) {
    return -1;
  }
  timespec now;
  gettime(&now);
  const auto& firstTime = waitForDelay.top().sendTime;
  const auto res = timeDifference(now, firstTime);
  if (res <= 0) {
    return 0;
  }
  return res;
}
XskSocket::XskSocket(size_t frameNum, size_t frameSize, const std::string& ifName, uint32_t queue_id) :
  frameSize(frameSize), frameNum(frameNum), queueId(queue_id), ifName(ifName)
{
  getMACFromIfName();
  bufBase = static_cast<uint8_t*>(mmap(nullptr, frameSize * frameNum, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
  if (bufBase == MAP_FAILED) {
    throw std::runtime_error("mmap failed");
  }
  xsk_umem_config umemCfg;
  umemCfg.fill_size = XSK_RING_PROD__DEFAULT_NUM_DESCS * 2;
  umemCfg.comp_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
  umemCfg.frame_size = frameSize;
  umemCfg.frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM;
  umemCfg.flags = 0;
  auto ret = xsk_umem__create(&umem, bufBase, frameSize * frameNum, &fq, &cq, &umemCfg);
  if (ret != 0) {
    throw std::runtime_error("Error creating a umem of size" + std::to_string(frameSize * frameNum) + stringerror(ret));
  }
  xsk_socket_config socketCfg;
  socketCfg.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
  socketCfg.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
  socketCfg.bind_flags = XDP_USE_NEED_WAKEUP;
  socketCfg.xdp_flags = XDP_FLAGS_SKB_MODE;
  socketCfg.libxdp_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD;
  ret = xsk_socket__create(&socket, ifName.c_str(), queue_id, umem, &rx, &tx, &socketCfg);
  if (ret != 0) {
    throw std::runtime_error("Error creating a xsk socket of if_name" + ifName + stringerror(ret));
  }
  {
    uint32_t fq_idx;
    xsk_ring_prod__reserve(&fq, frameNum, &fq_idx);
    for (uint64_t i = 0; i < frameNum; i++) {
      *xsk_ring_prod__fill_addr(&fq, fq_idx + i) = i * frameSize;
    }
    xsk_ring_prod__submit(&fq, frameNum);
  }
}
void XskSocket::fillFq() noexcept
{
  const auto fillSize = emptyFrameOffset.size();
  if (fillSize >= fillThreshold) {
    return;
  }
  uint32_t idx;
  if (xsk_ring_prod__reserve(&fq, fillSize, &idx) != fillSize) {
    return;
  }
  for (uint32_t i = 0; i < fillSize; i++) {
    *xsk_ring_prod__fill_addr(&fq, idx++) = emptyFrameOffset.back();
    emptyFrameOffset.pop_back();
  }
  xsk_ring_prod__submit(&fq, idx);
}
inline int XskSocket::wait(int timeout)
{
  sendDelayedPacket();
  recycle(128);
  return poll(fds.data(), fds.size(), static_cast<int>(std::min(static_cast<uint32_t>(timeout), static_cast<uint32_t>(firstTimeout()))));
}
[[nodiscard]] inline uint64_t XskSocket::frameOffset(const XskPacket& packet) const noexcept
{
  return reinterpret_cast<uint64_t>(packet.frame) - reinterpret_cast<uint64_t>(bufBase);
}
XskSocket::~XskSocket()
{
  xsk_socket__delete(socket);
  xsk_umem__delete(umem);
  munmap(bufBase, frameNum * frameSize);
}

int XskSocket::xskFd() const noexcept { return xsk_socket__fd(socket); }

void XskSocket::send(std::vector<XskDelayPacketInfo::XskFrameInfo>& packets)
{
  uint32_t idx;
  const auto packetSize = packets.size();
  if (xsk_ring_prod__reserve(&tx, packetSize, &idx) != packets.size()) {
    return;
  }

  for (const auto& i : packets) {
    *xsk_ring_prod__tx_desc(&tx, idx++) = {
      .addr = i.offset,
      .len = i.frameLen,
      .options = 0};
  }
  xsk_ring_prod__submit(&tx, packetSize);
  packets.clear();
}
std::vector<XskPacket> XskSocket::recv(uint32_t recvSizeMax, uint32_t* failedCount)
{
  uint32_t idx;
  std::vector<XskPacket> res;
  const auto recvSize = xsk_ring_cons__peek(&rx, recvSizeMax, &idx);
  if (recvSize <= 0) {
    return res;
  }
  const auto baseAddr = reinterpret_cast<uint64_t>(bufBase);
  uint32_t count = 0;
  for (uint32_t i = 0; i < recvSize; i++) {
    const auto* desc = xsk_ring_cons__rx_desc(&rx, idx++);
    res.emplace_back(reinterpret_cast<void*>(desc->addr + baseAddr), desc->len, frameSize);
    if (!res.back().parse()) {
      ++count;
      emptyFrameOffset.push_back(frameOffset(res.back()));
      res.pop_back();
    }
  }
  xsk_ring_cons__release(&rx, recvSize);
  if (failedCount) {
    *failedCount = count;
  }
  if (count > 0) {
    fillFq();
  }
  return res;
}
void XskSocket::sendDelayedPacket()
{
  timespec now;
  gettime(&now);
  std::vector<XskDelayPacketInfo::XskFrameInfo> packets;
  while (!waitForDelay.empty() && timeDifference(now, waitForDelay.top().sendTime) <= 0) {
    const auto& top = waitForDelay.top();
    packets.emplace_back(top);
  }
  if (!packets.empty()) {
    uint32_t idx;
    const auto sendSize = packets.size();
    if (xsk_ring_prod__reserve(&tx, sendSize, &idx) != sendSize) {
      throw std::runtime_error("Error in sending delayed packet");
    }
    for (const auto& i : packets) {
      *xsk_ring_prod__tx_desc(&tx, idx++) = {.addr = i.offset, .len = i.frameLen};
    }
    xsk_ring_prod__submit(&tx, sendSize);
  }
}
inline void XskSocket::recycle(size_t size) noexcept
{
  uint32_t idx;
  const auto completeSize = xsk_ring_cons__peek(&cq, size, &idx);
  if (completeSize <= 0) {
    return;
  }
  for (uint32_t i = 0; i < completeSize; ++i) {
    emptyFrameOffset.push_back(*xsk_ring_cons__comp_addr(&cq, idx++));
  }
  xsk_ring_cons__release(&cq, completeSize);
}
inline static int timeDifference(const timespec& t1, const timespec& t2) noexcept
{
  const auto res = t1.tv_sec * 1000 + t1.tv_nsec / 1000000L - (t2.tv_sec * 1000 + t2.tv_nsec / 1000000L);
  return static_cast<int>(res);
}
bool XskPacket::parse()
{
  // payloadEnd must bigger than payload + sizeof(ethhdr) + sizoef(iphdr) + sizeof(udphdr)
  auto* eth = reinterpret_cast<ethhdr*>(frame);
  uint8_t l4Protocol;
  if (eth->h_proto == htons(ETH_P_IP)) {
    auto* ip = reinterpret_cast<iphdr*>(eth + 1);
    if (ip->ihl != static_cast<uint8_t>(sizeof(iphdr) >> 2)) {
      // ip->ihl*4 != sizeof(iphdr)
      // ip options is not supported now!
      return false;
    }
    // check ip.check == ipv4Checksum() is not needed!
    // We check it in BPF program
    from = makeComboAddressFromRaw(4, reinterpret_cast<const char*>(&ip->saddr), sizeof(ip->saddr));
    to = makeComboAddressFromRaw(4, reinterpret_cast<const char*>(&ip->daddr), sizeof(ip->daddr));
    l4Protocol = ip->protocol;
    l4Header = reinterpret_cast<uint8_t*>(ip + 1);
    payloadEnd = std::min(reinterpret_cast<uint8_t*>(ip) + ip->tot_len, payloadEnd);
  }
  else if (eth->h_proto == htons(ETH_P_IPV6)) {
    auto* ipv6 = reinterpret_cast<ipv6hdr*>(eth + 1);
    l4Header = reinterpret_cast<uint8_t*>(ipv6 + 1);
    if (l4Header >= payloadEnd) {
      return false;
    }
    from = makeComboAddressFromRaw(6, reinterpret_cast<const char*>(&ipv6->saddr), sizeof(ipv6->saddr));
    to = makeComboAddressFromRaw(6, reinterpret_cast<const char*>(&ipv6->daddr), sizeof(ipv6->daddr));
    l4Protocol = ipv6->nexthdr;
    payloadEnd = std::min(l4Header + ipv6->payload_len, payloadEnd);
  }
  else {
    return false;
  }
  if (l4Protocol == IPPROTO_UDP) {
    // check udp.check == ipv4Checksum() is not needed!
    // We check it in BPF program
    auto* udp = reinterpret_cast<udphdr*>(l4Header);
    payload = l4Header + sizeof(udphdr);
    // Because of XskPacket::setHeader
    // payload = payloadEnd should be allow
    if (payload > payloadEnd) {
      return false;
    }
    payloadEnd = std::min(l4Header + udp->len, payloadEnd);
    from.setPort(ntohs(udp->source));
    to.setPort(ntohs(udp->dest));
    return true;
  }
  if (l4Protocol == IPPROTO_TCP) {
    // check tcp.check == ipv4Checksum() is not needed!
    // We check it in BPF program
    auto* tcp = reinterpret_cast<tcphdr*>(l4Header);
    if (tcp->doff != static_cast<uint32_t>(sizeof(tcphdr) >> 2)) {
      // tcp is not supported now!
      return false;
    }
    payload = l4Header + sizeof(tcphdr);
    //
    if (payload > payloadEnd) {
      return false;
    }
    from.setPort(ntohs(tcp->source));
    to.setPort(ntohs(tcp->dest));
    flags |= TCP;
    return true;
  }
  // ipv6 extension header is not supported now!
  return false;
}

inline uint32_t XskPacket::dataLen() const noexcept
{
  return payloadEnd - payload;
}
inline uint32_t XskPacket::FrameLen() const noexcept
{
  return payloadEnd - frame;
}
inline size_t XskPacket::capacity() const noexcept
{
  return frameEnd - payloadEnd;
}

void XskPacket::changeDirect() noexcept
{
  auto* eth = reinterpret_cast<ethhdr*>(frame);
  {
    uint8_t tmp[ETH_ALEN];
    static_assert(sizeof(tmp) == sizeof(eth->h_dest), "Size Error");
    static_assert(sizeof(tmp) == sizeof(eth->h_source), "Size Error");
    memcpy(tmp, eth->h_dest, sizeof(tmp));
    memcpy(eth->h_dest, eth->h_source, sizeof(tmp));
    memcpy(eth->h_source, tmp, sizeof(tmp));
  }
  void* transport;
  uint8_t transportLayerProtocol;
  if (eth->h_proto == htons(ETH_P_IPV6)) {
    // IPV6
    auto* ipv6 = reinterpret_cast<ipv6hdr*>(eth + 1);
    std::swap(ipv6->daddr, ipv6->saddr);
    transport = ipv6 + 1;
    transportLayerProtocol = ipv6->nexthdr;
  }
  else {
    // IPV4
    auto* ipv4 = reinterpret_cast<iphdr*>(eth + 1);
    std::swap(ipv4->daddr, ipv4->saddr);
    transport = ipv4 + 1;
    transportLayerProtocol = ipv4->protocol;
  }
  if (transportLayerProtocol == IPPROTO_UDP) {
    // UDP
    auto* udp = static_cast<udphdr*>(transport);
    std::swap(udp->dest, udp->source);
  }
  else {
    // TCP
    auto* tcp = static_cast<tcphdr*>(transport);
    std::swap(tcp->dest, tcp->source);
    // TODO
  }
}
inline bool XskPacket::isIPV6() const noexcept
{
  const auto* eth = reinterpret_cast<ethhdr*>(frame);
  return eth->h_proto == htons(ETH_P_IPV6);
}
XskPacket::XskPacket(void* frame, size_t dataSize, size_t frameSize) :
  frame(static_cast<uint8_t*>(frame)), payloadEnd(static_cast<uint8_t*>(frame) + dataSize), frameEnd(static_cast<uint8_t*>(frame) + frameSize)
{
}
PacketBuffer XskPacket::clonetoPacketBuffer() const
{
  const auto size = dataLen();
  PacketBuffer tmp(size);
  memcpy(tmp.data(), payload, size);
  return tmp;
}
bool XskPacket::setPayload(const PacketBuffer& buf)
{
  const auto bufSize = buf.size();
  if (bufSize == 0 || bufSize > capacity()) {
    return false;
  }
  flags |= UPDATE;
  memcpy(payload, buf.data(), bufSize);
  payloadEnd = payload + bufSize;
  return true;
}
void XskPacket::addDelay(const int relativeMilliseconds) noexcept
{
  gettime(&sendTime);
  sendTime.tv_nsec += static_cast<const uint64_t>(relativeMilliseconds) * 1000000L;
  sendTime.tv_sec += sendTime.tv_nsec / 1000000000L;
  sendTime.tv_nsec %= 1000000000L;
}
inline bool operator<(const XskDelayPacketInfo& s1, const XskDelayPacketInfo& s2) noexcept
{
  return s1.sendTime < s2.sendTime;
}
const ComboAddress& XskPacket::getFromAddr() const noexcept
{
  return from;
}
const ComboAddress& XskPacket::getToAddr() const noexcept
{
  return to;
}
void XskExtraInfo::notify(int fd)
{
  uint64_t value = 1;
  ssize_t res = 0;
  while ((res = write(fd, &value, sizeof(value))) == EINTR) {
  }
  if (res != 8) {
    throw runtime_error("Unable Wake Up XskSocket Failed");
  }
}
XskExtraInfo::XskExtraInfo()
{
  workerWaker = createEventfd();
  xskSocketWaker = createEventfd();
}
void* XskPacket::payloadData()
{
  return reinterpret_cast<void*>(payload);
}
const void* XskPacket::payloadData() const
{
  return reinterpret_cast<const void*>(payload);
}
void XskPacket::setAddr(const ComboAddress& from_, MACAddr fromMAC, const ComboAddress& to_, MACAddr toMAC, bool tcp) noexcept
{
  auto* eth = reinterpret_cast<ethhdr*>(frame);
  memcpy(eth->h_dest, &toMAC[0], sizeof(toMAC));
  memcpy(eth->h_source, &fromMAC[0], sizeof(fromMAC));
  to = to_;
  from = from_;

  if (tcp) {
    flags = TCP;
    payload = frame + sizeof(ethhdr) + (to.isIPv4() ? sizeof(iphdr) : sizeof(ipv6hdr)) + sizeof(tcphdr);
  }
  else {
    flags = 0;
    payload = frame + sizeof(ethhdr) + (to.isIPv4() ? sizeof(iphdr) : sizeof(ipv6hdr)) + sizeof(udphdr);
  }
}
void XskPacket::rewrite() noexcept
{
  flags |= REWIRTE;
  auto* eth = reinterpret_cast<ethhdr*>(frame);
  if (to.isIPv4()) {
    eth->h_proto = ETH_P_IP;
    auto* ip = reinterpret_cast<iphdr*>(eth + 1);

    ip->daddr = to.sin4.sin_addr.s_addr;
    ip->saddr = from.sin4.sin_addr.s_addr;
    if (flags & XskPacket::TCP) {
      auto* tcp = reinterpret_cast<tcphdr*>(ip + 1);
      ip->protocol = IPPROTO_TCP;
      tcp->source = from.sin4.sin_port;
      tcp->dest = to.sin4.sin_port;
      // TODO
    }
    else {
      auto* udp = reinterpret_cast<udphdr*>(ip + 1);
      ip->protocol = IPPROTO_UDP;
      udp->source = from.sin4.sin_port;
      udp->dest = to.sin4.sin_port;
      udp->len = htons(payloadEnd - reinterpret_cast<uint8_t*>(udp));
      udp->check = 0;
      udp->check = tcp_udp_v4_checksum();
    }
    ip->version = 4;
    ip->ihl = sizeof(iphdr) / 4;
    ip->tos = 0;
    ip->tot_len = htons(payloadEnd - reinterpret_cast<uint8_t*>(ip));
    ip->id = 0;
    ip->frag_off = 0;
    ip->ttl = DefaultTTL;
    ip->check = 0;
    ip->check = ipv4Checksum();
  }
  else {
    auto* ipv6 = reinterpret_cast<ipv6hdr*>(eth + 1);
    memcpy(&ipv6->daddr, &to.sin6.sin6_addr, sizeof(ipv6->daddr));
    memcpy(&ipv6->saddr, &from.sin6.sin6_addr, sizeof(ipv6->saddr));
    if (flags & XskPacket::TCP) {
      auto* tcp = reinterpret_cast<tcphdr*>(ipv6 + 1);
      ipv6->nexthdr = IPPROTO_TCP;
      tcp->source = from.sin6.sin6_port;
      tcp->dest = to.sin6.sin6_port;
      // TODO
    }
    else {
      auto* udp = reinterpret_cast<udphdr*>(ipv6 + 1);
      ipv6->nexthdr = IPPROTO_UDP;
      udp->source = from.sin6.sin6_port;
      udp->dest = to.sin6.sin6_port;
      udp->len = htons(payloadEnd - reinterpret_cast<uint8_t*>(udp));
      udp->check = 0;
      udp->check = tcp_udp_v6_checksum();
    }
    ipv6->version = 6;
    ipv6->priority = 0;
    ipv6->payload_len = htons(payloadEnd - reinterpret_cast<uint8_t*>(ipv6 + 1));
    ipv6->hop_limit = DefaultTTL;
    memset(&ipv6->flow_lbl, 0, sizeof(ipv6->flow_lbl));
  }
}

[[nodiscard]] __be16 XskPacket::ipv4Checksum() const noexcept
{
  auto* ip = reinterpret_cast<iphdr*>(frame + sizeof(iphdr));
  ip_checksum_fold(ip_checksum_partial(ip, sizeof(iphdr), 0));
}
[[nodiscard]] __be16 XskPacket::tcp_udp_v4_checksum() const noexcept
{
  const auto* ip = reinterpret_cast<iphdr*>(frame + sizeof(ethhdr));
  // ip options is not supported !!!
  const auto* l4Header = frame + sizeof(ethhdr) + sizeof(iphdr);
  const auto l4Length = static_cast<uint16_t>(payloadEnd - l4Header);
  auto sum = tcp_udp_v4_header_checksum_partial(ip->saddr, ip->daddr, ip->protocol, l4Length);
  sum = ip_checksum_partial(l4Header, l4Length, sum);
  return ip_checksum_fold(sum);
}
[[nodiscard]] __be16 XskPacket::tcp_udp_v6_checksum() const noexcept
{
  const auto* ipv6 = reinterpret_cast<ipv6hdr*>(frame + sizeof(ethhdr));
  const auto* l4Header = frame + sizeof(ethhdr) + sizeof(ipv6hdr);
  const auto l4Length = static_cast<uint16_t>(payloadEnd - l4Header);
  uint64_t sum = tcp_udp_v6_header_checksum_partial(&ipv6->saddr, &ipv6->daddr, ipv6->nexthdr, l4Length);
  sum = ip_checksum_partial(l4Header, l4Length, sum);
  return ip_checksum_fold(sum);
}

#ifndef __packed
#define __packed __attribute__((packed))
#endif
[[nodiscard]] inline uint64_t XskPacket::ip_checksum_partial(const void* p, size_t len, uint64_t sum) noexcept
{
  /* Main loop: 32 bits at a time.
   * We take advantage of intel's ability to do unaligned memory
   * accesses with minimal additional cost. Other architectures
   * probably want to be more careful here.
   */
  const uint32_t* p32 = (const uint32_t*)(p);
  for (; len >= sizeof(*p32); len -= sizeof(*p32))
    sum += *p32++;

  /* Handle un-32bit-aligned trailing bytes */
  const uint16_t* p16 = (const uint16_t*)(p32);
  if (len >= 2) {
    sum += *p16++;
    len -= sizeof(*p16);
  }
  if (len > 0) {
    const uint8_t* p8 = (const uint8_t*)(p16);
    sum += ntohs(*p8 << 8); /* RFC says pad last byte */
  }

  return sum;
}
[[nodiscard]] inline __be16 XskPacket::ip_checksum_fold(uint64_t sum) noexcept
{
  while (sum & ~0xffffffffULL)
    sum = (sum >> 32) + (sum & 0xffffffffULL);
  while (sum & 0xffff0000ULL)
    sum = (sum >> 16) + (sum & 0xffffULL);

  return ~sum;
}
[[nodiscard]] inline uint64_t XskPacket::tcp_udp_v4_header_checksum_partial(__be32 src_ip, __be32 dst_ip, uint8_t protocol, uint16_t len) noexcept
{
  struct header
  {
    __be32 src_ip;
    __be32 dst_ip;
    __uint8_t mbz;
    __uint8_t protocol;
    __be16 length;
  };
  /* The IPv4 pseudo-header is defined in RFC 793, Section 3.1. */
  struct ipv4_pseudo_header_t
  {
    /* We use a union here to avoid aliasing issues with gcc -O2 */
    union
    {
      header __packed fields;
      uint32_t words[3];
    };
  };
  struct ipv4_pseudo_header_t pseudo_header;
  assert(sizeof(pseudo_header) == 12);

  /* Fill in the pseudo-header. */
  pseudo_header.fields.src_ip = src_ip;
  pseudo_header.fields.dst_ip = dst_ip;
  pseudo_header.fields.mbz = 0;
  pseudo_header.fields.protocol = protocol;
  pseudo_header.fields.length = htons(len);
  return ip_checksum_partial(&pseudo_header, sizeof(pseudo_header), 0);
}
[[nodiscard]] inline uint64_t XskPacket::tcp_udp_v6_header_checksum_partial(const struct in6_addr* src_ip, const struct in6_addr* dst_ip, uint8_t protocol, uint32_t len) noexcept
{
  struct header
  {
    struct in6_addr src_ip;
    struct in6_addr dst_ip;
    __be32 length;
    __uint8_t mbz[3];
    __uint8_t next_header;
  };
  /* The IPv6 pseudo-header is defined in RFC 2460, Section 8.1. */
  struct ipv6_pseudo_header_t
  {
    /* We use a union here to avoid aliasing issues with gcc -O2 */
    union
    {
      header __packed fields;
      uint32_t words[10];
    };
  };
  struct ipv6_pseudo_header_t pseudo_header;
  assert(sizeof(pseudo_header) == 40);

  /* Fill in the pseudo-header. */
  pseudo_header.fields.src_ip = *src_ip;
  pseudo_header.fields.dst_ip = *dst_ip;
  pseudo_header.fields.length = htonl(len);
  memset(pseudo_header.fields.mbz, 0, sizeof(pseudo_header.fields.mbz));
  pseudo_header.fields.next_header = protocol;
  return ip_checksum_partial(&pseudo_header, sizeof(pseudo_header), 0);
}
void XskPacket::setHeader(const PacketBuffer& buf) noexcept
{
  memcpy(frame, buf.data(), buf.size());
  payloadEnd = frame + buf.size();
  flags = 0;
  const auto res = parse();
  assert(res);
}
std::unique_ptr<PacketBuffer> XskPacket::cloneHeadertoPacketBuffer() const
{
  const auto size = payload - frame;
  auto tmp = std::make_unique<PacketBuffer>(size);
  memcpy(tmp->data(), frame, size);
  return tmp;
}
int XskExtraInfo::createEventfd()
{
  auto fd = ::eventfd(0, EFD_CLOEXEC);
  if (fd < 0) {
    throw runtime_error("Unable create eventfd");
  }
  return fd;
}
void XskExtraInfo::waitForXskSocket() noexcept
{
  uint64_t x;
  read(workerWaker, &x, sizeof(x));
}
void XskExtraInfo::notifyXskSocket() noexcept
{
  notify(xskSocketWaker);
}

std::shared_ptr<XskExtraInfo> XskExtraInfo::create()
{
  return std::shared_ptr<XskExtraInfo>();
}
void XskSocket::addServer(std::shared_ptr<XskExtraInfo> s, ComboAddress src, bool isTCP)
{
  extern bool g_configurationDone;
  if (g_configurationDone) {
    throw runtime_error("Add a server with xsk at runtime is not supported");
  }
  auto fd = s->xskSocketWaker;
  if (extraInfos.count(fd)) {
    throw runtime_error("Server already exist");
  }
  routeTable[src] = s->xskSocketWaker;
  extraInfos[fd] = std::move(s);
  fds.push_back(pollfd{
    .fd = fd,
    .events = POLLIN,
  });
  s->umemBufBase = bufBase;
};
uint64_t XskExtraInfo::frameOffset(const XskPacket& s) const noexcept
{
  return s.frame - umemBufBase;
}
XskExtraInfo::~XskExtraInfo()
{
  close(workerWaker);
  close(xskSocketWaker);
}
void XskExtraInfo::notifyWorker() noexcept
{
  notify(workerWaker);
}
void XskSocket::getMACFromIfName()
{
  ifreq ifr;
  auto fd = ::socket(AF_INET, SOCK_DGRAM, 0);
  strncpy(ifr.ifr_name, ifName.c_str(), ifName.length() + 1);
  if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
    throw runtime_error("Error get MAC addr");
  }
  memcpy(source, ifr.ifr_hwaddr.sa_data, sizeof(source));
  close(fd);
}

XskDelayPacketInfo::XskDelayPacketInfo(XskPacket& packet, uint64_t umemOffset) :
  frame(umemOffset, packet.FrameLen())
{
  if (!(packet.flags & XskPacket::UPDATE)) {
    return;
  }
  flags = XskDelayPacketInfo::VALID;
  if (packet.flags & XskPacket::DELAY) {
    flags |= XskDelayPacketInfo::DELAY;
    sendTime = packet.sendTime;
  }
  if (!(packet.flags & XskPacket::REWIRTE)) {
    packet.changeDirect();
  }
}
