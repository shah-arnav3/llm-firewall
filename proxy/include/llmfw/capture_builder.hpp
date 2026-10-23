#pragma once
// Builds llmfw.v1.Frame captures from what the proxy observed.

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>

#include "capture.pb.h"
#include "llmfw/client_classifier.hpp"
#include "llmfw/common.hpp"
#include "llmfw/config.hpp"
#include "llmfw/counters.hpp"
#include "llmfw/http1_parser.hpp"

namespace llmfw {

/// Shared inputs for every builder. Both members outlive every capture.
struct CaptureBuildContext {
  const ClientClassifier& classifier;
  ProxyCounters& counters;  ///< Supplies capture ids.
};

/// What the proxy knows about a blind tunnel once it has closed.
struct TunnelObservation {
  std::uint64_t connection_id = 0;
  std::string_view host;  ///< Normalized if normalization succeeded, otherwise as the client sent it.
  std::uint16_t port = 0;
  TunnelReasonTag reason = TunnelReasonTag::kUnscopedHost;  ///< Never kNone.
  std::string_view connect_user_agent;
  std::uint64_t bytes_client_to_server = 0;
  std::uint64_t bytes_server_to_client = 0;
  std::int64_t start_unix_us = 0;  ///< When the tunnel was opened.
  std::chrono::microseconds duration{0};
};

/// Builds a Capture{tunnel}: metadata only, since tunnel bytes are never inspected.
/// Takes the next capture id from ctx.counters. The client path comes from the
/// CONNECT User-Agent, which is also copied into ClientInfo.user_agent.
[[nodiscard]] std::unique_ptr<llmfw::v1::Frame> buildTunnelCapture(const CaptureBuildContext& ctx,
                                                                   const TunnelObservation& tunnel);

/// What the proxy knows about a decrypted connection once it has closed.
struct DecryptedObservation {
  std::uint64_t connection_id = 0;
  std::string_view host;  ///< Normalized.
  std::uint16_t port = 0;
  std::string_view alpn;  ///< Negotiated with the client; empty means HTTP/1.1.
  std::string_view connect_user_agent;
  std::uint64_t bytes_client_to_server = 0;
  std::uint64_t bytes_server_to_client = 0;
  std::int64_t start_unix_us = 0;  ///< When the CONNECT arrived.
  std::chrono::microseconds duration{0};
  std::chrono::microseconds upstream_connect{0};
  std::chrono::microseconds client_handshake{0};
};

/// Builds a Capture{decrypted} for the connection as a whole. It holds no content.
/// Takes the next capture id from ctx.counters. The client path comes from the CONNECT
/// User-Agent, which is also copied into ClientInfo.user_agent.
[[nodiscard]] std::unique_ptr<llmfw::v1::Frame> buildDecryptedCapture(const CaptureBuildContext& ctx,
                                                                      const DecryptedObservation& connection);

/// What every exchange on one decrypted connection shares.
struct ExchangeConnection {
  std::uint64_t connection_id = 0;
  std::string connect_host;  ///< Normalized.
  std::uint16_t connect_port = 0;
  std::string alpn;  ///< Negotiated with the client; empty means HTTP/1.1.
  std::string connect_user_agent;
  std::chrono::microseconds upstream_connect{0};
  std::chrono::microseconds client_handshake{0};
};

/// Builds one Capture{http} from a request and its response as they are parsed.
/// Call the setters in wire order: request head, request complete, response head,
/// response complete; any may be missing when the exchange ends early. finish() may be called at any point, once.
///
/// What it keeps:
///   - Headers in wire order. Values of capture.redact_headers (any case) are
///     removed, keeping only the name and the original value length.
///   - The client: the request's User-Agent if it has one, otherwise the CONNECT's,
///     classified by the rules; if that is UNKNOWN, by the CONNECT User-Agent.
///   - Timings relative to the request's first byte. The connection's
///     upstream_connect and client_handshake only on exchange_index 0.
class ExchangeCaptureBuilder {
 public:
  /// The references must outlive the builder. `started` is when the request's first byte was read.
  ExchangeCaptureBuilder(const CaptureBuildContext& ctx, const CaptureConfig& cfg,
                         const ExchangeConnection& connection, std::uint32_t exchange_index, Clock::time_point started,
                         std::int64_t started_unix_us);

  void setRequestHead(const Http1Head& head);
  void markRequestComplete(Clock::time_point at);
  /// `at` is when the response's first byte was read.
  void setResponseHead(const Http1Head& head, Clock::time_point at);
  void markResponseComplete(Clock::time_point at);

  /// Whether setRequestHead was called with a HEAD request.
  [[nodiscard]] bool isHeadRequest() const;

  /// The finished frame. Takes the next capture id from ctx.counters.
  [[nodiscard]] std::unique_ptr<llmfw::v1::Frame> finish(ExchangeOutcomeTag outcome);

 private:
  [[nodiscard]] std::uint64_t sinceStart(Clock::time_point at) const;

  const CaptureBuildContext& ctx_;
  const CaptureConfig& cfg_;
  const ExchangeConnection& connection_;
  Clock::time_point started_;
  std::unique_ptr<llmfw::v1::Frame> frame_;
  std::string request_user_agent_;
  bool head_request_ = false;
};

/// A frame's size for the capture queue's byte budget: its serialized size.
[[nodiscard]] std::size_t approximateFrameBytes(const llmfw::v1::Frame& frame);

}  // namespace llmfw
