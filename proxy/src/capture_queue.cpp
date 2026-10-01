#include "llmfw/capture_queue.hpp"

#include "llmfw/capture_builder.hpp"

namespace llmfw {

CaptureQueue::CaptureQueue(std::size_t max_items, std::size_t max_bytes, ProxyCounters& counters)
    : max_items_(max_items), max_bytes_(max_bytes), counters_(counters) {}

bool CaptureQueue::tryPush(std::unique_ptr<llmfw::v1::Frame> frame) {
  if (!frame) {
    return false;
  }
  // Sized outside the lock so the critical section stays O(1).
  const std::size_t size = approximateFrameBytes(*frame);
  std::size_t depth = 0;
  {
    const std::lock_guard lock(mu_);
    if (closed_ || entries_.size() >= max_items_ || size > max_bytes_ - bytes_) {
      counters_.captures_dropped_queue_full.fetch_add(1, std::memory_order_relaxed);
      return false;
    }
    entries_.push_back(Entry{std::move(frame), size});
    bytes_ += size;
    depth = entries_.size();
  }
  counters_.observeQueueDepth(depth);
  cv_.notify_one();
  return true;
}

std::unique_ptr<llmfw::v1::Frame> CaptureQueue::popWait(std::chrono::milliseconds timeout) {
  std::unique_lock lock(mu_);
  if (!cv_.wait_for(lock, timeout, [this] { return !entries_.empty() || closed_; }) || entries_.empty()) {
    return nullptr;
  }
  Entry entry = std::move(entries_.front());
  entries_.pop_front();
  bytes_ -= entry.bytes;
  return std::move(entry.frame);
}

void CaptureQueue::close() {
  {
    const std::lock_guard lock(mu_);
    closed_ = true;
  }
  cv_.notify_all();
}

std::size_t CaptureQueue::items() const {
  const std::lock_guard lock(mu_);
  return entries_.size();
}

std::size_t CaptureQueue::bytes() const {
  const std::lock_guard lock(mu_);
  return bytes_;
}

}  // namespace llmfw
