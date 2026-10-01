#include <gtest/gtest.h>

#include <atomic>
#include <thread>
#include <vector>

#include "llmfw/capture_builder.hpp"
#include "llmfw/capture_queue.hpp"

namespace llmfw {
namespace {

using std::chrono::milliseconds;

/// A frame whose host field makes its serialized size grow with `host_bytes`.
std::unique_ptr<llmfw::v1::Frame> frameWithId(std::uint64_t id, std::size_t host_bytes = 8) {
  auto frame = std::make_unique<llmfw::v1::Frame>();
  frame->mutable_capture()->set_capture_id(id);
  frame->mutable_capture()->mutable_tunnel()->set_host(std::string(host_bytes, 'h'));
  return frame;
}

std::uint64_t dropped(const ProxyCounters& counters) { return counters.captures_dropped_queue_full.load(); }

TEST(CaptureQueue, PushThenPopPreservesOrder) {
  ProxyCounters counters;
  CaptureQueue queue(10, 1 << 20, counters);
  for (std::uint64_t id = 1; id <= 3; ++id) {
    ASSERT_TRUE(queue.tryPush(frameWithId(id)));
  }
  for (std::uint64_t id = 1; id <= 3; ++id) {
    auto frame = queue.popWait(milliseconds(10));
    ASSERT_NE(frame, nullptr);
    EXPECT_EQ(frame->capture().capture_id(), id);
  }
  EXPECT_EQ(queue.items(), 0u);
  EXPECT_EQ(queue.bytes(), 0u);
}

TEST(CaptureQueue, DropsWhenItemLimitReachedAndCounts) {
  ProxyCounters counters;
  CaptureQueue queue(2, 1 << 20, counters);
  EXPECT_TRUE(queue.tryPush(frameWithId(1)));
  EXPECT_TRUE(queue.tryPush(frameWithId(2)));
  EXPECT_FALSE(queue.tryPush(frameWithId(3)));
  EXPECT_FALSE(queue.tryPush(frameWithId(4)));
  EXPECT_EQ(dropped(counters), 2u);
  EXPECT_EQ(queue.items(), 2u);
}

TEST(CaptureQueue, DropsWhenByteLimitReachedAndCounts) {
  ProxyCounters counters;
  const std::size_t one = approximateFrameBytes(*frameWithId(1, 100));
  CaptureQueue queue(100, 2 * one, counters);
  EXPECT_TRUE(queue.tryPush(frameWithId(1, 100)));
  EXPECT_TRUE(queue.tryPush(frameWithId(2, 100)));
  EXPECT_EQ(queue.bytes(), 2 * one);
  EXPECT_FALSE(queue.tryPush(frameWithId(3, 100)));
  EXPECT_EQ(dropped(counters), 1u);
  // Popping frees budget again.
  ASSERT_NE(queue.popWait(milliseconds(10)), nullptr);
  EXPECT_TRUE(queue.tryPush(frameWithId(4, 100)));
}

TEST(CaptureQueue, DropsSingleFrameLargerThanByteLimit) {
  ProxyCounters counters;
  CaptureQueue queue(100, 64, counters);
  EXPECT_FALSE(queue.tryPush(frameWithId(1, 1000)));
  EXPECT_EQ(dropped(counters), 1u);
  EXPECT_EQ(queue.items(), 0u);
}

TEST(CaptureQueue, IgnoresNullFrameWithoutCounting) {
  ProxyCounters counters;
  CaptureQueue queue(10, 1 << 20, counters);
  EXPECT_FALSE(queue.tryPush(nullptr));
  EXPECT_EQ(dropped(counters), 0u);
}

TEST(CaptureQueue, TryPushNeverWaitsForConsumer) {
  ProxyCounters counters;
  CaptureQueue queue(1, 1 << 20, counters);
  ASSERT_TRUE(queue.tryPush(frameWithId(1)));
  // Nothing consumes, so a waiting push would hang here.
  const auto start = Clock::now();
  for (int i = 0; i < 1000; ++i) {
    EXPECT_FALSE(queue.tryPush(frameWithId(2)));
  }
  EXPECT_LT(Clock::now() - start, milliseconds(500));
  EXPECT_EQ(dropped(counters), 1000u);
}

TEST(CaptureQueue, PopWaitTimesOut) {
  ProxyCounters counters;
  CaptureQueue queue(10, 1 << 20, counters);
  const auto start = Clock::now();
  EXPECT_EQ(queue.popWait(milliseconds(50)), nullptr);
  EXPECT_GE(Clock::now() - start, milliseconds(45));
}

TEST(CaptureQueue, PopWaitWakesOnPush) {
  ProxyCounters counters;
  CaptureQueue queue(10, 1 << 20, counters);
  std::thread producer([&] {
    std::this_thread::sleep_for(milliseconds(20));
    ASSERT_TRUE(queue.tryPush(frameWithId(7)));
  });
  auto frame = queue.popWait(milliseconds(5000));
  producer.join();
  ASSERT_NE(frame, nullptr);
  EXPECT_EQ(frame->capture().capture_id(), 7u);
}

TEST(CaptureQueue, CloseRejectsPushAndDrainsRemaining) {
  ProxyCounters counters;
  CaptureQueue queue(10, 1 << 20, counters);
  ASSERT_TRUE(queue.tryPush(frameWithId(1)));
  ASSERT_TRUE(queue.tryPush(frameWithId(2)));
  queue.close();
  EXPECT_FALSE(queue.tryPush(frameWithId(3)));
  EXPECT_EQ(dropped(counters), 1u);
  EXPECT_EQ(queue.popWait(milliseconds(1000))->capture().capture_id(), 1u);
  EXPECT_EQ(queue.popWait(milliseconds(1000))->capture().capture_id(), 2u);
  const auto start = Clock::now();
  EXPECT_EQ(queue.popWait(milliseconds(5000)), nullptr);
  EXPECT_LT(Clock::now() - start, milliseconds(1000));
}

TEST(CaptureQueue, CloseWakesWaitingConsumer) {
  ProxyCounters counters;
  CaptureQueue queue(10, 1 << 20, counters);
  std::thread closer([&] {
    std::this_thread::sleep_for(milliseconds(20));
    queue.close();
  });
  const auto start = Clock::now();
  EXPECT_EQ(queue.popWait(milliseconds(5000)), nullptr);
  closer.join();
  EXPECT_LT(Clock::now() - start, milliseconds(1000));
}

TEST(CaptureQueue, TracksHighWatermark) {
  ProxyCounters counters;
  CaptureQueue queue(10, 1 << 20, counters);
  for (std::uint64_t id = 1; id <= 4; ++id) {
    ASSERT_TRUE(queue.tryPush(frameWithId(id)));
  }
  for (int i = 0; i < 3; ++i) {
    ASSERT_NE(queue.popWait(milliseconds(10)), nullptr);
  }
  ASSERT_TRUE(queue.tryPush(frameWithId(5)));
  EXPECT_EQ(counters.queue_high_watermark_items.load(), 4u);
}

TEST(CaptureQueue, ConcurrentProducersRespectBounds) {
  ProxyCounters counters;
  constexpr std::size_t kMaxItems = 50;
  constexpr int kProducers = 8;
  constexpr int kPerProducer = 2000;
  CaptureQueue queue(kMaxItems, 1 << 20, counters);

  std::atomic<std::uint64_t> accepted{0};
  std::atomic<bool> producing{true};
  std::atomic<std::uint64_t> consumed{0};
  std::thread consumer([&] {
    while (producing.load() || queue.items() > 0) {
      if (queue.popWait(milliseconds(1))) {
        consumed.fetch_add(1);
      }
      EXPECT_LE(queue.items(), kMaxItems);
    }
  });
  std::vector<std::thread> producers;
  for (int p = 0; p < kProducers; ++p) {
    producers.emplace_back([&] {
      for (int i = 0; i < kPerProducer; ++i) {
        if (queue.tryPush(frameWithId(1))) {
          accepted.fetch_add(1);
        }
      }
    });
  }
  for (std::thread& t : producers) {
    t.join();
  }
  producing.store(false);
  consumer.join();

  constexpr std::uint64_t kTotal = std::uint64_t{kProducers} * kPerProducer;
  EXPECT_EQ(accepted.load() + dropped(counters), kTotal);
  EXPECT_EQ(consumed.load(), accepted.load());
  EXPECT_LE(counters.queue_high_watermark_items.load(), kMaxItems);
}

}  // namespace
}  // namespace llmfw
