#pragma once
// Turns the two byte streams of a decrypted HTTP/1.1 connection into exchange captures.

#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "capture.pb.h"
#include "llmfw/capture_builder.hpp"
#include "llmfw/http1_parser.hpp"
#include "llmfw/relay_observer.hpp"

namespace llmfw {

/// What an Http1ExchangeTracker hands on when a 101 accepts a WebSocket upgrade.
struct UpgradeHandoff {
  WebSocketConnection connection;  ///< From the upgrade exchange, as it was pushed.
  std::vector<std::uint8_t> client_bytes;  ///< Client bytes sent after the upgrade request.
  Clock::time_point client_bytes_at{};     ///< When the last of them was read.
  std::vector<std::uint8_t> upstream_bytes;  ///< Origin bytes after the 101 in the same chunk.
  Clock::time_point upstream_bytes_at{};
};

/// Where an Http1ExchangeTracker sends what it produces.
struct ExchangeSinks {
  /// Each finished exchange, in the order the exchanges finish.
  std::function<void(std::unique_ptr<llmfw::v1::Frame>)> push;
  /// Called once when either direction stops parsing as HTTP/1.1.
  std::function<void()> parse_error;
  /// Called once, after the upgrade exchange is pushed, when a 101 accepts a request
  /// whose Upgrade header names websocket. May be empty.
  std::function<void(UpgradeHandoff)> upgraded;
};

/// Parses each direction with its own Http1Parser and pairs requests with responses
/// in order (pipelining included). Each request head starts an exchange; the final
/// response that completes it pushes one Capture{http} with outcome kComplete.
///   - A HEAD request's response has no body; 1xx responses other than 101 are skipped.
///   - A response that finishes before its request has been fully sent completes the
///     exchange; the rest of that request is not recorded.
///   - A response with no request waiting is not recorded.
///   - On a framing error in either direction, every exchange in progress is pushed
///     with kParseError, parse_error is called, and nothing more is recorded.
///   - Upgrades: after an Upgrade request, client bytes are held back from the request
///     parser (up to kMaxHeldUpgradeBytes) until its response arrives. A 101 pushes
///     that exchange with kUpgraded, and nothing more is recorded; a WebSocket upgrade
///     is handed to sinks.upgraded with the bytes that follow it. Any other final
///     response means the server refused, so parsing resumes with the held bytes.
///     More than kMaxHeldUpgradeBytes while waiting counts as a framing error.
///   - onClosed completes a response delimited by the close, then pushes every
///     exchange still in progress with the given outcome.
class Http1ExchangeTracker final : public RelayObserver {
 public:
  /// The most client bytes held back while an upgrade is waiting for its response.
  static constexpr std::size_t kMaxHeldUpgradeBytes = 64 * 1024;

  /// `ctx`, `cfg` and `connection` must outlive the tracker.
  Http1ExchangeTracker(const CaptureBuildContext& ctx, const CaptureConfig& cfg, CaptureMode mode,
                       const ExchangeConnection& connection, ExchangeSinks sinks);
  ~Http1ExchangeTracker() override;

  void onClientBytes(std::span<const std::uint8_t> bytes, Clock::time_point at) override;
  void onUpstreamBytes(std::span<const std::uint8_t> bytes, Clock::time_point at) override;
  void onClosed(ExchangeOutcomeTag unfinished) override;
  /// The User-Agent of the first request that sent one.
  [[nodiscard]] std::string clientUserAgent() const override;

 private:
  class RequestEvents;
  class ResponseEvents;
  struct Exchange {
    std::unique_ptr<ExchangeCaptureBuilder> builder;
    bool request_complete = false;
    bool response_started = false;
    bool websocket = false;  ///< The request's Upgrade header names websocket.
  };

  void feedRequests(std::span<const std::uint8_t> bytes);
  void handle(const FeedResult& result);
  void failParse();
  void finishFront(ExchangeOutcomeTag outcome);
  void stop(ExchangeOutcomeTag outcome);

  const CaptureBuildContext& ctx_;
  const CaptureConfig& cfg_;
  CaptureMode mode_;
  const ExchangeConnection& connection_;
  ExchangeSinks sinks_;
  std::unique_ptr<RequestEvents> request_events_;
  std::unique_ptr<ResponseEvents> response_events_;
  Http1Parser request_parser_;
  Http1Parser response_parser_;
  std::deque<Exchange> in_flight_;
  std::uint32_t next_exchange_index_ = 0;
  std::string client_user_agent_;
  bool capturing_ = true;
  /// Whether the newest exchange's request is still being parsed.
  bool request_open_ = false;
  /// An Upgrade request is waiting for its response; client bytes go to held_.
  bool upgrade_pending_ = false;
  /// The upgrade was refused: resume the request parser once the response feed returns.
  bool resume_requests_ = false;
  std::vector<std::uint8_t> held_;
  /// Set when a WebSocket upgrade exchange is pushed, until the handoff.
  std::optional<WebSocketConnection> upgrade_;
  /// When the bytes being parsed in each direction arrived. A message starts at the
  /// first chunk read after the previous message in its direction ended.
  Clock::time_point request_chunk_at_{};
  std::optional<Clock::time_point> request_started_at_;
  Clock::time_point response_chunk_at_{};
  std::optional<Clock::time_point> response_started_at_;
};

}  // namespace llmfw
