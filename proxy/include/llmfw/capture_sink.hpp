#pragma once
// The drain thread and its sink interface. There is exactly one sink per process.

#include <atomic>
#include <chrono>
#include <thread>

#include "capture.pb.h"
#include "llmfw/capture_queue.hpp"
#include "llmfw/counters.hpp"

namespace llmfw {

/// Where captures go. Only the drain thread calls these methods.
class FrameSink {
 public:
  virtual ~FrameSink() = default;
  /// Delivers one frame. Returns false if it could not be delivered, and the drain
  /// counts captures_dropped_ipc_unavailable. Must not block longer than one write.
  [[nodiscard]] virtual bool write(const llmfw::v1::Frame& frame) = 0;
  /// Called at least once a second, for periodic work such as flushing or rotation.
  virtual void tick(std::chrono::steady_clock::time_point now) = 0;
  /// Called once, last, when the drain stops.
  virtual void close() = 0;
};

/// Pops from CaptureQueue and writes to the FrameSink on its own thread.
class CaptureDrain {
 public:
  CaptureDrain(CaptureQueue& queue, FrameSink& sink, ProxyCounters& counters);
  /// Stops with no grace period if still running.
  ~CaptureDrain();
  CaptureDrain(const CaptureDrain&) = delete;
  CaptureDrain& operator=(const CaptureDrain&) = delete;

  /// Starts the thread. Call at most once.
  void start();

  /// Closes the queue, keeps writing what is left until the queue is empty or `grace`
  /// has passed, calls sink.close() and joins. Frames still queued after `grace` are
  /// discarded. Safe to call more than once and before start().
  void stop(std::chrono::milliseconds grace);

 private:
  void run();

  CaptureQueue& queue_;
  FrameSink& sink_;
  ProxyCounters& counters_;
  std::atomic<bool> stopped_{false};   ///< stop() has run.
  std::atomic<bool> stopping_{false};  ///< Read by the drain thread; set after deadline_.
  std::atomic<std::chrono::steady_clock::rep> deadline_{0};
  std::thread thread_;
};

}  // namespace llmfw
