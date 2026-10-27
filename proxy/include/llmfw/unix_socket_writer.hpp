#pragma once
// The full-mode sink: varint-delimited llmfw.v1.Frame messages over a Unix domain socket to the collector.

#include <chrono>
#include <cstdint>
#include <string>

#include "capture.pb.h"
#include "llmfw/capture_sink.hpp"
#include "llmfw/config.hpp"
#include "llmfw/counters.hpp"

namespace llmfw {

/// Sends frames to the collector's socket at cfg.socketPath(). It never reads from the
/// socket, and only the drain thread calls it.
///
/// Connecting happens in tick(), first on the first tick and then whenever the backoff
/// has expired. It refuses to connect unless socket_dir is a private directory and the
/// socket is ours (see fs_util). Once connected it sends Frame{hello}, then
/// Frame{stats}. Any failure closes the socket and schedules the next attempt
/// reconnect_backoff_initial later, doubling after each failed attempt up to
/// reconnect_backoff_max; a successful connect resets the backoff.
///
/// write() returns false, so the drain counts the frame as dropped, when:
///   - the writer is not connected;
///   - the frame is larger than cfg.max_frame_bytes (the connection stays up);
///   - sending fails, including a send blocked for longer than `send_timeout` by a
///     collector that has stopped reading. The connection is then closed.
/// A peer that closes its end never raises SIGPIPE.
class UnixSocketWriter final : public FrameSink {
 public:
  static constexpr std::chrono::milliseconds kDefaultSendTimeout{2000};

  /// `counters` must outlive the writer; stats frames are snapshots of it.
  UnixSocketWriter(IpcConfig cfg, std::string proxy_instance_id, std::string proxy_version,
                   std::int64_t started_unix_ms, ProxyCounters& counters,
                   std::chrono::milliseconds send_timeout = kDefaultSendTimeout);
  ~UnixSocketWriter() override;
  UnixSocketWriter(const UnixSocketWriter&) = delete;
  UnixSocketWriter& operator=(const UnixSocketWriter&) = delete;

  [[nodiscard]] bool write(const llmfw::v1::Frame& frame) override;
  /// Connects when an attempt is due, and sends Frame{stats} every cfg.stats_interval.
  void tick(std::chrono::steady_clock::time_point now) override;
  void close() override;

  [[nodiscard]] bool connected() const;

 private:
  void tryConnect(std::chrono::steady_clock::time_point now);
  void scheduleRetry(std::chrono::steady_clock::time_point now, const std::string& why);
  [[nodiscard]] bool send(const llmfw::v1::Frame& frame);
  [[nodiscard]] bool sendStats();
  void disconnect();

  IpcConfig cfg_;
  std::string proxy_instance_id_;
  std::string proxy_version_;
  std::int64_t started_unix_ms_;
  ProxyCounters& counters_;
  std::chrono::milliseconds send_timeout_;
  int fd_ = -1;
  std::chrono::milliseconds backoff_;
  std::chrono::steady_clock::time_point next_connect_attempt_{};
  std::chrono::steady_clock::time_point next_stats_{};
  /// A failure has been logged since the last connect, so later ones are not.
  bool failure_logged_ = false;
};

}  // namespace llmfw
