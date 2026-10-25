#include "llmfw/websocket_tracker.hpp"

#include <utility>

namespace llmfw {

WebSocketTracker::WebSocketTracker(const CaptureBuildContext& ctx, const CaptureConfig& cfg, CaptureMode mode,
                                   WebSocketConnection connection, WebSocketSinks sinks)
    : ctx_(ctx),
      mode_(mode),
      connection_(std::move(connection)),
      sinks_(std::move(sinks)),
      client_{WsSender::kClient, WebSocketFrameDecoder(WsSender::kClient, cfg.websocket_message_cap_bytes)},
      upstream_{WsSender::kServer, WebSocketFrameDecoder(WsSender::kServer, cfg.websocket_message_cap_bytes)} {}

void WebSocketTracker::onClientBytes(std::span<const std::uint8_t> bytes, Clock::time_point at) {
  feed(client_, bytes, at);
}

void WebSocketTracker::onUpstreamBytes(std::span<const std::uint8_t> bytes, Clock::time_point at) {
  feed(upstream_, bytes, at);
}

void WebSocketTracker::feed(Side& side, std::span<const std::uint8_t> bytes, Clock::time_point at) {
  if (side.failed) {
    return;
  }
  const std::int64_t at_unix_us = unixMicros(at);
  const WsDecodeResult result = side.decoder.feed(bytes, [&](WsMessage&& message) {
    sinks_.push(
        buildWebSocketCapture(ctx_, mode_, connection_, side.sender, side.next_index++, std::move(message), at_unix_us));
  });
  if (result.status == WsDecodeStatus::kError) {
    side.failed = true;
    if (sinks_.decode_error) {
      sinks_.decode_error();
    }
  }
}

}  // namespace llmfw
