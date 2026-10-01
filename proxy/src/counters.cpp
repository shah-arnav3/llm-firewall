#include "llmfw/counters.hpp"

#include <chrono>

#include "capture.pb.h"

namespace llmfw {

namespace {

std::uint64_t load(const std::atomic<std::uint64_t>& counter) { return counter.load(std::memory_order_relaxed); }

}  // namespace

void ProxyCounters::snapshotInto(llmfw::v1::ProxyStats& out, const std::string& proxy_instance_id) const {
  out.set_proxy_instance_id(proxy_instance_id);
  out.set_as_of_unix_ms(std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::system_clock::now().time_since_epoch())
                            .count());
  out.set_connections_accepted(load(connections_accepted));
  out.set_captures_created(load(captures_created));
  out.set_captures_dropped_queue_full(load(captures_dropped_queue_full));
  out.set_captures_dropped_ipc_unavailable(load(captures_dropped_ipc_unavailable));
  out.set_request_bodies_truncated(load(request_bodies_truncated));
  out.set_response_bodies_truncated(load(response_bodies_truncated));
  out.set_ws_messages_truncated(load(ws_messages_truncated));
  out.set_tunnels_unscoped(load(tunnels_unscoped));
  out.set_tunnels_scoped_no_cert(load(tunnels_scoped_no_cert));
  out.set_tunnels_upstream_verify_failed(load(tunnels_upstream_verify_failed));
  out.set_tunnels_client_tls_breaker(load(tunnels_client_tls_breaker));
  out.set_client_tls_handshake_failures(load(client_tls_handshake_failures));
  out.set_http_parse_errors(load(http_parse_errors));
  out.set_non_connect_requests_rejected(load(non_connect_requests_rejected));
  out.set_queue_high_watermark_items(load(queue_high_watermark_items));
}

std::uint64_t ProxyCounters::nextCaptureId() {
  captures_created.fetch_add(1, std::memory_order_relaxed);
  return next_capture_id_.fetch_add(1, std::memory_order_relaxed);
}

void ProxyCounters::observeQueueDepth(std::uint64_t items) {
  std::uint64_t seen = queue_high_watermark_items.load(std::memory_order_relaxed);
  while (items > seen && !queue_high_watermark_items.compare_exchange_weak(seen, items, std::memory_order_relaxed)) {
  }
}

}  // namespace llmfw
