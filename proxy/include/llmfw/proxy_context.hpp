#pragma once
// Process-wide objects shared by every connection.

#include "llmfw/capture_builder.hpp"
#include "llmfw/capture_queue.hpp"
#include "llmfw/config.hpp"
#include "llmfw/counters.hpp"
#include "llmfw/host_scope.hpp"

namespace llmfw {

/// Everything here outlives every connection. Members are either immutable after
/// startup or internally synchronized, so any I/O thread may use them.
struct ProxyContext {
  const ProxyConfig& config;
  const HostScope& scope;
  CaptureQueue& queue;
  ProxyCounters& counters;
  const CaptureBuildContext& build;
};

}  // namespace llmfw
