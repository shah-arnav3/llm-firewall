#pragma once
// Process-wide objects shared by every connection, and the application that owns them.

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

/// Process exit codes of llmfw-proxy.
enum ExitCode : int {
  kExitOk = 0,
  kExitUnexpected = 1,  ///< An unexpected exception.
  kExitConfig = 2,      ///< Bad command line or configuration.
  kExitSink = 3,        ///< The metadata log cannot be opened.
  kExitBind = 4,        ///< The listen address cannot be bound.
};

/// Owns the io_context and its threads, every shared object, the drain thread and its sink.
///
/// run():
///   - Rejects proxy.mode "full" (kExitConfig): decryption is not implemented.
///   - Startup: instance id -> metadata log (kExitSink on failure) -> shared objects ->
///     drain -> listener (kExitBind on failure) -> listen.io_threads I/O threads.
///   - Shutdown, on SIGINT, SIGTERM or requestStop(): stop accepting -> close every open
///     tunnel (each is still captured) -> once they have finished, or after 2 s, stop
///     the I/O threads -> drain the queue to the log for up to 2 s -> log a counter
///     summary -> return kExitOk (kExitUnexpected if an I/O thread threw).
/// If the proxy is not running, Claude's PAC falls back to DIRECT, so only logging is lost.
class ProxyApp {
 public:
  explicit ProxyApp(ProxyConfig config);
  ~ProxyApp();
  ProxyApp(const ProxyApp&) = delete;
  ProxyApp& operator=(const ProxyApp&) = delete;

  /// Blocks until shutdown and returns an ExitCode. Call once.
  [[nodiscard]] int run();

  /// Starts a graceful shutdown. Safe from any thread, before or during run().
  void requestStop();

 private:
  struct State;
  ProxyConfig config_;
  std::mutex mu_;
  State* state_ = nullptr;  ///< Set while run() is serving; guarded by mu_.
  bool stop_requested_ = false;
};

}  // namespace llmfw
