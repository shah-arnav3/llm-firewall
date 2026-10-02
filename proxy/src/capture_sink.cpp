#include "llmfw/capture_sink.hpp"

namespace llmfw {

namespace {

using SteadyClock = std::chrono::steady_clock;

// Short enough that stop() and the once-a-second tick are never delayed noticeably.
constexpr std::chrono::milliseconds kPopTimeout{250};
constexpr std::chrono::seconds kTickInterval{1};

}  // namespace

CaptureDrain::CaptureDrain(CaptureQueue& queue, FrameSink& sink, ProxyCounters& counters)
    : queue_(queue), sink_(sink), counters_(counters) {}

CaptureDrain::~CaptureDrain() { stop(std::chrono::milliseconds(0)); }

void CaptureDrain::start() { thread_ = std::thread([this] { run(); }); }

void CaptureDrain::stop(std::chrono::milliseconds grace) {
  if (stopped_.exchange(true)) {
    return;
  }
  deadline_.store((SteadyClock::now() + grace).time_since_epoch().count(), std::memory_order_relaxed);
  stopping_.store(true, std::memory_order_release);
  queue_.close();
  if (thread_.joinable()) {
    thread_.join();
  } else {
    sink_.close();
  }
}

void CaptureDrain::run() {
  SteadyClock::time_point last_tick = SteadyClock::now();
  while (true) {
    const bool stopping = stopping_.load(std::memory_order_acquire);
    if (stopping && SteadyClock::now().time_since_epoch().count() >= deadline_.load(std::memory_order_relaxed)) {
      break;
    }
    if (const auto frame = queue_.popWait(kPopTimeout)) {
      if (!sink_.write(*frame)) {
        counters_.captures_dropped_ipc_unavailable.fetch_add(1, std::memory_order_relaxed);
      }
    } else if (stopping) {
      break;  // The queue is closed and empty.
    }
    const SteadyClock::time_point now = SteadyClock::now();
    if (now - last_tick >= kTickInterval) {
      sink_.tick(now);
      last_tick = now;
    }
  }
  sink_.close();
}

}  // namespace llmfw
