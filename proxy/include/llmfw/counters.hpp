#pragma once
// Process-wide proxy counters. Any thread can increment them without locking.
// Snapshots are sent to the collector as llmfw.v1.ProxyStats.

#include <atomic>
#include <cstdint>
#include <string>

namespace llmfw::v1 {
class ProxyStats;
}

namespace llmfw {

/// Each field matches the ProxyStats field of the same name. All values are
/// cumulative since process start.
struct ProxyCounters {
  std::atomic<std::uint64_t> connections_accepted{0};
  std::atomic<std::uint64_t> captures_created{0};
  std::atomic<std::uint64_t> captures_dropped_queue_full{0};
  std::atomic<std::uint64_t> captures_dropped_ipc_unavailable{0};
  std::atomic<std::uint64_t> request_bodies_truncated{0};
  std::atomic<std::uint64_t> response_bodies_truncated{0};
  std::atomic<std::uint64_t> ws_messages_truncated{0};
  std::atomic<std::uint64_t> tunnels_unscoped{0};
  std::atomic<std::uint64_t> tunnels_scoped_no_cert{0};
  std::atomic<std::uint64_t> tunnels_upstream_verify_failed{0};
  std::atomic<std::uint64_t> tunnels_client_tls_breaker{0};
  std::atomic<std::uint64_t> client_tls_handshake_failures{0};
  std::atomic<std::uint64_t> http_parse_errors{0};
  std::atomic<std::uint64_t> non_connect_requests_rejected{0};
  std::atomic<std::uint64_t> queue_high_watermark_items{0};

  /// Copies every counter (relaxed loads) into `out`, along with the instance id and
  /// the current wall-clock time as as_of_unix_ms. The copy is not one atomic
  /// snapshot: counters can move while it is taken.
  void snapshotInto(llmfw::v1::ProxyStats& out, const std::string& proxy_instance_id) const;

  /// Hands out the next capture id (starting at 1) and increments captures_created.
  /// A dropped capture keeps the id it was given, so the collector sees the gap.
  [[nodiscard]] std::uint64_t nextCaptureId();

  /// Raises queue_high_watermark_items to `items` if it is higher. Safe from any thread.
  void observeQueueDepth(std::uint64_t items);

 private:
  std::atomic<std::uint64_t> next_capture_id_{1};
};

}  // namespace llmfw
