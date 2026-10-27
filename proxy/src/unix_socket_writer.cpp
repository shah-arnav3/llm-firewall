#include "llmfw/unix_socket_writer.hpp"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <string>
#include <utility>

#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

#include <google/protobuf/io/coded_stream.h>
#include <google/protobuf/io/zero_copy_stream_impl_lite.h>

#include "llmfw/fs_util.hpp"
#include "llmfw/log.hpp"

namespace llmfw {

namespace {

constexpr std::uint32_t kProtocolVersion = 1;

std::string errnoText(const std::string& what) { return what + ": " + std::strerror(errno); }

/// The frame as it goes on the wire: its size as a varint, then its bytes.
std::string delimited(const llmfw::v1::Frame& frame) {
  std::string out;
  {
    google::protobuf::io::StringOutputStream stream(&out);
    google::protobuf::io::CodedOutputStream coded(&stream);
    coded.WriteVarint32(static_cast<std::uint32_t>(frame.ByteSizeLong()));
    frame.SerializeWithCachedSizes(&coded);
  }
  return out;
}

}  // namespace

UnixSocketWriter::UnixSocketWriter(IpcConfig cfg, std::string proxy_instance_id, std::string proxy_version,
                                   std::int64_t started_unix_ms, ProxyCounters& counters,
                                   std::chrono::milliseconds send_timeout)
    : cfg_(std::move(cfg)),
      proxy_instance_id_(std::move(proxy_instance_id)),
      proxy_version_(std::move(proxy_version)),
      started_unix_ms_(started_unix_ms),
      counters_(counters),
      send_timeout_(send_timeout),
      backoff_(cfg_.reconnect_backoff_initial) {}

UnixSocketWriter::~UnixSocketWriter() { disconnect(); }

bool UnixSocketWriter::write(const llmfw::v1::Frame& frame) {
  if (!connected() || frame.ByteSizeLong() > cfg_.max_frame_bytes) {
    return false;
  }
  if (!send(frame)) {
    scheduleRetry(std::chrono::steady_clock::now(), errnoText("sending to the collector failed"));
    return false;
  }
  return true;
}

void UnixSocketWriter::tick(std::chrono::steady_clock::time_point now) {
  if (!connected()) {
    if (now >= next_connect_attempt_) {
      tryConnect(now);
    }
    return;
  }
  if (now >= next_stats_) {
    if (!sendStats()) {
      scheduleRetry(now, errnoText("sending to the collector failed"));
      return;
    }
    next_stats_ = now + cfg_.stats_interval;
  }
}

void UnixSocketWriter::close() { disconnect(); }

bool UnixSocketWriter::connected() const { return fd_ >= 0; }

void UnixSocketWriter::tryConnect(std::chrono::steady_clock::time_point now) {
  const std::filesystem::path path = cfg_.socketPath();
  if (!isPrivateDirectory(cfg_.socket_dir)) {
    scheduleRetry(now, "the collector socket directory " + cfg_.socket_dir.string() +
                           " is missing, not ours, or not mode 0700");
    return;
  }
  if (!isOwnSocket(path)) {
    scheduleRetry(now, "no collector socket of ours at " + path.string());
    return;
  }
  fd_ = ::socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd_ < 0) {
    scheduleRetry(now, errnoText("socket"));
    return;
  }
  const int on = 1;
  const timeval timeout{.tv_sec = static_cast<time_t>(send_timeout_.count() / 1000),
                        .tv_usec = static_cast<suseconds_t>((send_timeout_.count() % 1000) * 1000)};
  sockaddr_un addr{};
  addr.sun_family = AF_UNIX;
  path.string().copy(addr.sun_path, sizeof(addr.sun_path) - 1);
  if (::setsockopt(fd_, SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof(on)) != 0 ||
      ::setsockopt(fd_, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) != 0 ||
      ::connect(fd_, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) != 0) {
    scheduleRetry(now, errnoText("connecting to the collector at " + path.string()));
    return;
  }
  llmfw::v1::Frame hello;
  llmfw::v1::StreamHello& h = *hello.mutable_hello();
  h.set_protocol_version(kProtocolVersion);
  h.set_proxy_instance_id(proxy_instance_id_);
  h.set_proxy_version(proxy_version_);
  h.set_started_unix_ms(started_unix_ms_);
  if (!send(hello) || !sendStats()) {
    scheduleRetry(now, errnoText("sending to the collector failed"));
    return;
  }
  logInfo("connected to the collector at " + path.string());
  backoff_ = cfg_.reconnect_backoff_initial;
  failure_logged_ = false;
  next_stats_ = now + cfg_.stats_interval;
}

void UnixSocketWriter::scheduleRetry(std::chrono::steady_clock::time_point now, const std::string& why) {
  disconnect();
  if (!failure_logged_) {
    logWarn(why + "; captures are dropped until it is reachable");
    failure_logged_ = true;
  }
  next_connect_attempt_ = now + backoff_;
  backoff_ = std::min(backoff_ * 2, cfg_.reconnect_backoff_max);
}

bool UnixSocketWriter::send(const llmfw::v1::Frame& frame) {
  const std::string wire = delimited(frame);
  std::size_t sent = 0;
  while (sent < wire.size()) {
    const ssize_t n = ::send(fd_, wire.data() + sent, wire.size() - sent, 0);
    if (n < 0 && errno == EINTR) {
      continue;
    }
    if (n <= 0) {
      return false;  // Includes EAGAIN once SO_SNDTIMEO expires; part of the frame may be on the wire.
    }
    sent += static_cast<std::size_t>(n);
  }
  return true;
}

bool UnixSocketWriter::sendStats() {
  llmfw::v1::Frame stats;
  counters_.snapshotInto(*stats.mutable_stats(), proxy_instance_id_);
  return send(stats);
}

void UnixSocketWriter::disconnect() {
  if (fd_ >= 0) {
    ::close(fd_);
    fd_ = -1;
  }
}

}  // namespace llmfw
