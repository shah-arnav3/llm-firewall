#pragma once
// Bounded, drop-on-full hand-off from the I/O threads (producers) to the single
// drain thread (consumer).

#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <deque>
#include <memory>
#include <mutex>

#include "capture.pb.h"
#include "llmfw/counters.hpp"

namespace llmfw {

/// Invariants:
///   * items() <= max_items and bytes() <= max_bytes at all times.
///   * tryPush never waits for the consumer. Its only critical section is an O(1)
///     deque push under a mutex, so an I/O thread is never blocked by a slow writer.
///   * Every rejected frame increments captures_dropped_queue_full exactly once.
///   * queue_high_watermark_items tracks the most items ever queued at once.
/// A frame's size for the byte budget is approximateFrameBytes().
class CaptureQueue {
 public:
  /// @param max_items, max_bytes both at least 1.
  CaptureQueue(std::size_t max_items, std::size_t max_bytes, ProxyCounters& counters);

  /// Returns false and drops the frame if it would exceed either bound, or if the
  /// queue is closed. A single frame larger than max_bytes is always dropped. A null
  /// frame is ignored and returns false without counting.
  [[nodiscard]] bool tryPush(std::unique_ptr<llmfw::v1::Frame> frame);

  /// Waits up to `timeout` for a frame. Returns nullptr on timeout, or once the queue
  /// is closed and empty.
  [[nodiscard]] std::unique_ptr<llmfw::v1::Frame> popWait(std::chrono::milliseconds timeout);

  /// After close, tryPush returns false and popWait returns what is left without waiting.
  void close();

  [[nodiscard]] std::size_t items() const;
  [[nodiscard]] std::size_t bytes() const;

 private:
  struct Entry {
    std::unique_ptr<llmfw::v1::Frame> frame;
    std::size_t bytes;
  };
  const std::size_t max_items_;
  const std::size_t max_bytes_;
  ProxyCounters& counters_;
  mutable std::mutex mu_;
  std::condition_variable cv_;
  std::deque<Entry> entries_;
  std::size_t bytes_ = 0;
  bool closed_ = false;
};

}  // namespace llmfw
