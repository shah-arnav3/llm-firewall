#pragma once
// Builds llmfw.v1.Frame captures from what the proxy observed.

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string_view>

#include "capture.pb.h"
#include "llmfw/client_classifier.hpp"
#include "llmfw/common.hpp"
#include "llmfw/counters.hpp"

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

/// A frame's size for the capture queue's byte budget: its serialized size.
[[nodiscard]] std::size_t approximateFrameBytes(const llmfw::v1::Frame& frame);

}  // namespace llmfw
