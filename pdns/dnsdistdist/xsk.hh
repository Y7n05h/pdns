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

#pragma once
#include "iputils.hh"
#include "misc.hh"
#include "noinitvector.hh"
#include "lock.hh"

#include <array>
#include <bits/types/struct_timespec.h>
#include <boost/lockfree/spsc_queue.hpp>
#include <cstdint>
#include <cstring>
#include <linux/types.h>
#include <memory>
#include <queue>
#include <stdexcept>
#include <string>
#include <sys/poll.h>
#include <sys/types.h>
#include <unistd.h>
#include <unordered_map>
#include <vector>
#include <xdp/xsk.h>

class XskPacket;
class XskExtraInfo;
class XskSocket;

#ifdef HAVE_XSK
struct XskFrameInfo
{
  uint64_t offset;
  uint32_t frameLen;

public:
  XskFrameInfo(uint64_t offset_, uint32_t frameLen_) :
    offset(offset_), frameLen(frameLen_) {}
  XskFrameInfo(const XskFrameInfo&) = default;
  XskFrameInfo() = default;
};
class XskDelayPacketInfo
{

  XskFrameInfo frame;
  timespec sendTime;

  friend bool operator<(const XskDelayPacketInfo& s1, const XskDelayPacketInfo& s2) noexcept;
  friend XskSocket;
  friend void XskRouter(std::shared_ptr<XskSocket> xsk);
  uint8_t flags;
  enum Flag : uint8_t
  {
    VALID = 1 << 0,
    DELAY = 1 << 1,
  };

public:
  XskDelayPacketInfo() = default;
  XskDelayPacketInfo(const XskDelayPacketInfo&) = default;
  XskDelayPacketInfo(XskPacket& packet, uint64_t umemOffset);
};
// Only used for XskSocket::waitForDelay
bool operator<(const XskDelayPacketInfo& s1, const XskDelayPacketInfo& s2) noexcept;
class XskSocket
{
  const size_t holdThreshold = 256;
  const size_t fillThreshold = 128;
  const size_t frameNum;
  const size_t frameSize;
  const uint32_t queueId;
  std::priority_queue<XskDelayPacketInfo> waitForDelay;
  std::string ifName;
  std::unordered_map<uint16_t, int> routeTable;
  std::unordered_map<int, std::shared_ptr<XskExtraInfo>> extraInfos;
  uint8_t* bufBase;
  vector<pollfd> fds;
  vector<uint64_t> uniqueEmptyFrameOffset;
  xsk_ring_cons cq;
  xsk_ring_cons rx;
  xsk_ring_prod fq;
  xsk_ring_prod tx;
  xsk_socket* socket;
  xsk_umem* umem;
  bpf_object* prog;
  constexpr static bool isPowOfTwo(uint32_t value) noexcept;
  [[nodiscard]] static int timeDifference(const timespec& t1, const timespec& t2) noexcept;
  friend void XskRouter(std::shared_ptr<XskSocket> xsk);

  [[nodiscard]] uint64_t frameOffset(const XskPacket& packet) const noexcept;
  int firstTimeout();
  void fillFq() noexcept;
  void recycle(size_t size) noexcept;
  void getMACFromIfName();
  void pickUpReadyPacket(std::vector<XskFrameInfo>& packets);

public:
  std::shared_ptr<LockGuarded<vector<uint64_t>>> sharedEmptyFrameOffset;
  XskSocket(size_t frameNum, size_t frameSize, const std::string& ifName, uint32_t queue_id, std::string xskMapPath);
  MACAddr source;
  ~XskSocket();
  [[nodiscard]] int xskFd() const noexcept;
  int wait(int timeout);
  void send(std::vector<XskFrameInfo>& packets);
  std::vector<XskPacket> recv(uint32_t recvSizeMax, uint32_t* failedCount);
  void addWorker(std::shared_ptr<XskExtraInfo> s, uint16_t port, bool isTCP);
};
class XskPacket
{
  ComboAddress from;
  ComboAddress to;
  uint8_t* frame;
  uint8_t* l4Header;
  uint8_t* payload;
  uint8_t* payloadEnd;
  uint8_t* frameEnd;
  timespec sendTime;
  uint32_t flags{0};

  friend XskSocket;
  friend XskExtraInfo;
  friend XskDelayPacketInfo;

  enum Flags : uint32_t
  {
    TCP = 1 << 0,
    UPDATE = 1 << 1,
    DELAY = 1 << 3,
    REWIRTE = 1 << 4
  };

  constexpr static uint8_t DefaultTTL = 64;
  bool parse();
  void changeDirectAndUpdateChecksum() noexcept;

  // You must set ipHeader.check = 0 before call this method
  [[nodiscard]] __be16 ipv4Checksum() const noexcept;
  // You must set l4Header.check = 0 before call this method
  // ip options is not supported
  [[nodiscard]] __be16 tcp_udp_v4_checksum() const noexcept;
  // You must set l4Header.check = 0 before call this method
  [[nodiscard]] __be16 tcp_udp_v6_checksum() const noexcept;
  [[nodiscard]] static uint64_t ip_checksum_partial(const void* p, size_t len, uint64_t sum) noexcept;
  [[nodiscard]] static __be16 ip_checksum_fold(uint64_t sum) noexcept;
  [[nodiscard]] static uint64_t tcp_udp_v4_header_checksum_partial(__be32 src_ip, __be32 dst_ip, uint8_t protocol, uint16_t len) noexcept;
  [[nodiscard]] static uint64_t tcp_udp_v6_header_checksum_partial(const struct in6_addr* src_ip, const struct in6_addr* dst_ip, uint8_t protocol, uint32_t len) noexcept;
  void rewriteIpv4Header(void* ipv4header) noexcept;
  void rewriteIpv6Header(void* ipv6header) noexcept;

public:
  [[nodiscard]] const ComboAddress& getFromAddr() const noexcept;
  [[nodiscard]] const ComboAddress& getToAddr() const noexcept;
  [[nodiscard]] const void* payloadData() const;
  [[nodiscard]] bool isIPV6() const noexcept;
  [[nodiscard]] size_t capacity() const noexcept;
  [[nodiscard]] uint32_t dataLen() const noexcept;
  [[nodiscard]] uint32_t FrameLen() const noexcept;
  [[nodiscard]] PacketBuffer clonePacketBuffer() const;
  void cloneIntoPacketBuffer(PacketBuffer& buffer) const;
  [[nodiscard]] std::unique_ptr<PacketBuffer> cloneHeadertoPacketBuffer() const;
  [[nodiscard]] void* payloadData();
  void setAddr(const ComboAddress& from_, MACAddr fromMAC, const ComboAddress& to_, MACAddr toMAC, bool tcp = false) noexcept;
  bool setPayload(const PacketBuffer& buf);
  void rewrite() noexcept;
  void setHeader(const PacketBuffer& buf) noexcept;
  XskPacket() = default;
  XskPacket(void* frame, size_t dataSize, size_t frameSize);
  void addDelay(int relativeMilliseconds) noexcept;
};
class XskExtraInfo : std::enable_shared_from_this<XskExtraInfo>
{
  using XskPacketRing = boost::lockfree::spsc_queue<XskPacket, boost::lockfree::capacity<512>>;
  using XskDelayPacketRing = boost::lockfree::spsc_queue<XskDelayPacketInfo, boost::lockfree::capacity<512>>;

public:
  XskExtraInfo();
  int workerWaker;
  int xskSocketWaker;
  uint8_t* umemBufBase;
  std::shared_ptr<LockGuarded<vector<uint64_t>>> sharedEmptyFrameOffset;
  vector<uint64_t> uniqueEmptyFrameOffset;
  XskPacketRing cq;
  XskDelayPacketRing sq;
  size_t frameSize;

  static int createEventfd();
  static void notify(int fd);
  static std::shared_ptr<XskExtraInfo> create();
  void notifyWorker() noexcept;
  void notifyXskSocket() noexcept;
  void waitForXskSocket() noexcept;
  void cleanWorkerNotification() noexcept;
  void cleanSocketNotification() noexcept;
  ~XskExtraInfo();
  [[nodiscard]] uint64_t frameOffset(const XskPacket& s) const noexcept;
  void fillUniqueEmptyOffset();
  void* getEmptyframe();
};
std::vector<pollfd> getPollFdsForWorker(XskExtraInfo& info);
#else
struct XskFrameInfo
{
};
class XskDelayPacketInfo
{
};
class XskSocket
{
};
class XskPacket
{
};
class XskExtraInfo : std::enable_shared_from_this<XskExtraInfo>
{
};

#endif /* HAVE_XSK */
