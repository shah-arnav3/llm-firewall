#pragma once
// Process-wide objects shared by every connection.

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <unordered_map>

#include "llmfw/capture_builder.hpp"
#include "llmfw/capture_queue.hpp"
#include "llmfw/config.hpp"
#include "llmfw/counters.hpp"
#include "llmfw/host_scope.hpp"

namespace llmfw {

class BlindTunnel;

/// The open tunnels, so shutdown can close them and still capture them. Thread-safe.
class TunnelRegistry {
 public:
  /// Registers an open tunnel. Returns false once closeAll() has been called; the
  /// tunnel must then close itself.
  [[nodiscard]] bool add(std::uint64_t connection_id, std::weak_ptr<BlindTunnel> tunnel);

  /// Removes a tunnel. After closeAll(), removing the last one calls the on_empty callback.
  void remove(std::uint64_t connection_id);

  /// Refuses new tunnels, asks every open one to close, and calls `on_empty` (on the
  /// thread that removes the last tunnel, or right away if none are open).
  void closeAll(std::function<void()> on_empty);

  [[nodiscard]] std::size_t size() const;

 private:
  mutable std::mutex mu_;
  std::unordered_map<std::uint64_t, std::weak_ptr<BlindTunnel>> open_;
  bool closing_ = false;
  std::function<void()> on_empty_;
};

/// Everything here outlives every connection. Members are either immutable after
/// startup or internally synchronized, so any I/O thread may use them.
struct ProxyContext {
  const ProxyConfig& config;
  const HostScope& scope;
  CaptureQueue& queue;
  ProxyCounters& counters;
  const CaptureBuildContext& build;
  TunnelRegistry& tunnels;
};

}  // namespace llmfw
