#pragma once
// Turns the two byte streams of an upgraded WebSocket connection into message captures.

#include <cstdint>
#include <functional>
#include <memory>
#include <span>

#include "capture.pb.h"
#include "llmfw/capture_builder.hpp"
#include "llmfw/common.hpp"
#include "llmfw/config.hpp"
#include "llmfw/websocket.hpp"

namespace llmfw {

/// Where a WebSocketTracker sends what it produces.
struct WebSocketSinks {
  /// Each complete message, in the order the messages complete.
  std::function<void(std::unique_ptr<llmfw::v1::Frame>)> push;
  /// Called once for each direction that stops decoding as WebSocket.
  std::function<void()> decode_error;
};

/// Decodes each direction with its own WebSocketFrameDecoder (client frames masked,
/// origin frames not), capped at capture.websocket_message_cap_bytes. Each complete
/// message pushes one Capture{websocket}, numbered per direction from 0 and timed by
/// the chunk that completed it. After a protocol error in one direction, decode_error
/// is called and that direction records nothing more; the other carries on. A message
/// still incomplete when the bytes stop is not recorded.
class WebSocketTracker {
 public:
  /// `ctx` and `cfg` must outlive the tracker.
  WebSocketTracker(const CaptureBuildContext& ctx, const CaptureConfig& cfg, CaptureMode mode,
                   WebSocketConnection connection, WebSocketSinks sinks);

  void onClientBytes(std::span<const std::uint8_t> bytes, Clock::time_point at);
  void onUpstreamBytes(std::span<const std::uint8_t> bytes, Clock::time_point at);

 private:
  struct Side {
    WsSender sender;
    WebSocketFrameDecoder decoder;
    std::uint32_t next_index = 0;
    bool failed = false;
  };

  void feed(Side& side, std::span<const std::uint8_t> bytes, Clock::time_point at);

  const CaptureBuildContext& ctx_;
  CaptureMode mode_;
  WebSocketConnection connection_;
  WebSocketSinks sinks_;
  Side client_;
  Side upstream_;
};

}  // namespace llmfw
