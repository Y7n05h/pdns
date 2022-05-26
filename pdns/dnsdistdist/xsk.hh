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
#include "dnsdist-idstate.hh"
#include "iputils.hh"
#include "lock.hh"
#include "misc.hh"
#include "noinitvector.hh"

#include <array>
#include <bits/types/struct_timespec.h>
#include <boost/lockfree/spsc_queue.hpp>
#include <cstdint>
#include <cstring>
#include <linux/if_ether.h>
#include <linux/if_link.h>
#include <linux/ip.h>
#include <linux/types.h>
#include <linux/udp.h>
#include <memory>
#include <queue>
#include <stdexcept>
#include <string>
#include <sys/eventfd.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <type_traits>
#include <unistd.h>
#include <unordered_map>
#include <vector>
#include <xdp/libxdp.h>
#include <xdp/xsk.h>

class XskPacket;
class XskExtraInfo;
using MACAddr = uint8_t[6];
class XskSocket;
class XskDelayPacketInfo
{

  struct XskFrameInfo
  {
    uint64_t offset;
    uint32_t frameLen;

  public:
    XskFrameInfo(uint64_t offset, uint32_t frameLen) :
      offset(offset), frameLen(frameLen) {}
    XskFrameInfo() = default;
  };
  XskFrameInfo frame;
  timespec sendTime;

  friend inline bool operator<(const XskDelayPacketInfo& s1, const XskDelayPacketInfo& s2) noexcept;
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
  XskDelayPacketInfo(XskPacket& packet, uint64_t umemOffset);
};

class XskSocket : std::enable_shared_from_this<XskPacket>
{
  const size_t fillThreshold = 64;
  const size_t frameNum;
  const size_t frameSize;
  const uint32_t queueId;
  std::priority_queue<XskDelayPacketInfo> waitForDelay;
  std::string ifName;
  std::unordered_map<ComboAddress, int, ComboAddress::addressPortOnlyHash> routeTable;
  std::unordered_map<int, std::shared_ptr<XskExtraInfo>> extraInfos;
  uint8_t* bufBase;
  vector<pollfd> fds;
  vector<uint64_t> emptyFrameOffset;
  xsk_ring_cons cq;
  xsk_ring_cons rx;
  xsk_ring_prod fq;
  xsk_ring_prod tx;
  xsk_socket* socket;
  xsk_umem* umem;
  inline constexpr static bool is_pow_of_two(uint32_t value) noexcept;
  inline static int timeDifference(const timespec& t1, const timespec& t2) noexcept;
  friend void XskRouter(std::shared_ptr<XskSocket> xsk);

  [[nodiscard]] inline uint64_t frameOffset(const XskPacket& packet) const noexcept;
  inline int firstTimeout();
  inline void fillFq() noexcept;
  inline void recycle(size_t size) noexcept;
  void getMACFromIfName();
  void sendDelayedPacket();
  XskSocket(size_t frameNum, size_t frameSize, const std::string& ifName, uint32_t queue_id);

public:
  MACAddr source;
  template <class... Args>
  [[nodiscard]] static std::shared_ptr<XskSocket> create(Args&&... args)
  {
    return std::move(std::make_shared<XskSocket>(std::forward(args)...));
  }
  ~XskSocket();
  [[nodiscard]] int xskFd() const noexcept;
  inline int wait(int timeout);
  void send(std::vector<XskDelayPacketInfo::XskFrameInfo>& packets);
  std::vector<XskPacket> recv(uint32_t recvSizeMax, uint32_t* failedCount);
  void addServer(std::shared_ptr<XskExtraInfo> s, ComboAddress source, bool isTCP);
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
  void changeDirect() noexcept;

  // You must set ipHeader.check = 0 before call this method
  [[nodiscard]] inline __be16 ipv4Checksum() const noexcept;
  // You must set l4Header.check = 0 before call this method
  // ip options is not supported
  [[nodiscard]] inline __be16 tcp_udp_v4_checksum() const noexcept;
  // You must set l4Header.check = 0 before call this method
  [[nodiscard]] inline __be16 tcp_udp_v6_checksum() const noexcept;
  [[nodiscard]] static inline uint64_t ip_checksum_partial(const void* p, size_t len, uint64_t sum) noexcept;
  [[nodiscard]] static inline __be16 ip_checksum_fold(uint64_t sum) noexcept;
  [[nodiscard]] static inline uint64_t tcp_udp_v4_header_checksum_partial(__be32 src_ip, __be32 dst_ip, uint8_t protocol, uint16_t len) noexcept;
  [[nodiscard]] static inline uint64_t tcp_udp_v6_header_checksum_partial(const struct in6_addr* src_ip, const struct in6_addr* dst_ip, uint8_t protocol, uint32_t len) noexcept;

public:
  [[nodiscard]] const ComboAddress& getFromAddr() const noexcept;
  [[nodiscard]] const ComboAddress& getToAddr() const noexcept;
  [[nodiscard]] const void* payloadData() const;
  [[nodiscard]] inline bool isIPV6() const noexcept;
  [[nodiscard]] inline size_t capacity() const noexcept;
  [[nodiscard]] inline uint32_t dataLen() const noexcept;
  [[nodiscard]] inline uint32_t FrameLen() const noexcept;
  [[nodiscard]] PacketBuffer clonetoPacketBuffer() const;
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
// Only used for XskSocket::waitForDelay
inline bool operator<(const XskDelayPacketInfo& s1, const XskDelayPacketInfo& s2) noexcept;
class XskExtraInfo : std::enable_shared_from_this<XskExtraInfo>
{
  XskExtraInfo();
  using XskPacketRing = boost::lockfree::spsc_queue<XskPacket, boost::lockfree::capacity<512>>;
  using XskDelayPacketRing = boost::lockfree::spsc_queue<XskDelayPacketInfo, boost::lockfree::capacity<512>>;

public:
  static std::shared_ptr<XskExtraInfo> create();
  int workerWaker;
  int xskSocketWaker;
  uint8_t* umemBufBase;
  XskPacketRing cq;
  XskDelayPacketRing sq;

  static int createEventfd();
  static void notify(int fd);
  void notifyWorker() noexcept;
  void notifyXskSocket() noexcept;
  void waitForXskSocket() noexcept;
  ~XskExtraInfo();
  [[nodiscard]] uint64_t frameOffset(const XskPacket& s) const noexcept;
};
