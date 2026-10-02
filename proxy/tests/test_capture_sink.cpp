#include <gtest/gtest.h>

#include <vector>

#include "llmfw/capture_sink.hpp"

namespace llmfw {
namespace {

using std::chrono::milliseconds;
using SteadyClock = std::chrono::steady_clock;

/// Records what the drain hands it. Read only after the drain has stopped (joined).
class FakeSink final : public FrameSink {
 public:
  bool accept = true;
  milliseconds write_delay{0};
  std::vector<std::uint64_t> written_ids;
  int ticks = 0;
  int closes = 0;

  bool write(const llmfw::v1::Frame& frame) override {
    if (write_delay.count() > 0) {
      std::this_thread::sleep_for(write_delay);
    }
    if (accept) {
      written_ids.push_back(frame.capture().capture_id());
    }
    return accept;
  }
  void tick(SteadyClock::time_point /*now*/) override { ++ticks; }
  void close() override { ++closes; }
};

std::unique_ptr<llmfw::v1::Frame> frameWithId(std::uint64_t id) {
  auto frame = std::make_unique<llmfw::v1::Frame>();
  frame->mutable_capture()->set_capture_id(id);
  return frame;
}

struct Fixture {
  ProxyCounters counters;
  CaptureQueue queue{1000, 1 << 20, counters};
  FakeSink sink;
};

TEST(CaptureDrain, WritesFramesInOrder) {
  Fixture f;
  CaptureDrain drain(f.queue, f.sink, f.counters);
  drain.start();
  for (std::uint64_t id = 1; id <= 50; ++id) {
    ASSERT_TRUE(f.queue.tryPush(frameWithId(id)));
  }
  drain.stop(milliseconds(5000));
  ASSERT_EQ(f.sink.written_ids.size(), 50u);
  for (std::uint64_t id = 1; id <= 50; ++id) {
    EXPECT_EQ(f.sink.written_ids[id - 1], id);
  }
  EXPECT_EQ(f.sink.closes, 1);
}

TEST(CaptureDrain, CountsFailedWritesAsIpcUnavailable) {
  Fixture f;
  f.sink.accept = false;
  CaptureDrain drain(f.queue, f.sink, f.counters);
  drain.start();
  for (std::uint64_t id = 1; id <= 5; ++id) {
    ASSERT_TRUE(f.queue.tryPush(frameWithId(id)));
  }
  drain.stop(milliseconds(5000));
  EXPECT_EQ(f.counters.captures_dropped_ipc_unavailable.load(), 5u);
}

TEST(CaptureDrain, StopDrainsQueuedFramesWithinGrace) {
  Fixture f;
  for (std::uint64_t id = 1; id <= 100; ++id) {
    ASSERT_TRUE(f.queue.tryPush(frameWithId(id)));
  }
  CaptureDrain drain(f.queue, f.sink, f.counters);
  drain.start();
  drain.stop(milliseconds(5000));
  EXPECT_EQ(f.sink.written_ids.size(), 100u);
  EXPECT_FALSE(f.queue.tryPush(frameWithId(101))) << "stop() must close the queue";
}

TEST(CaptureDrain, StopGivesUpAfterGrace) {
  Fixture f;
  f.sink.write_delay = milliseconds(20);
  for (std::uint64_t id = 1; id <= 100; ++id) {
    ASSERT_TRUE(f.queue.tryPush(frameWithId(id)));
  }
  CaptureDrain drain(f.queue, f.sink, f.counters);
  drain.start();
  const auto start = SteadyClock::now();
  drain.stop(milliseconds(100));
  const auto took = SteadyClock::now() - start;
  EXPECT_LT(f.sink.written_ids.size(), 100u);
  EXPECT_LT(took, milliseconds(1000));
  EXPECT_EQ(f.sink.closes, 1);
}

TEST(CaptureDrain, TicksAtLeastOncePerSecond) {
  Fixture f;
  CaptureDrain drain(f.queue, f.sink, f.counters);
  drain.start();
  std::this_thread::sleep_for(milliseconds(2300));
  drain.stop(milliseconds(0));
  EXPECT_GE(f.sink.ticks, 2);
}

TEST(CaptureDrain, ClosesSinkExactlyOnce) {
  Fixture f;
  {
    CaptureDrain drain(f.queue, f.sink, f.counters);
    drain.start();
    drain.stop(milliseconds(0));
    drain.stop(milliseconds(0));
  }  // The destructor must not close again.
  EXPECT_EQ(f.sink.closes, 1);
}

TEST(CaptureDrain, DestructorStopsRunningDrain) {
  Fixture f;
  {
    CaptureDrain drain(f.queue, f.sink, f.counters);
    drain.start();
  }
  EXPECT_EQ(f.sink.closes, 1);
}

TEST(CaptureDrain, StopBeforeStartClosesSinkAndQueue) {
  Fixture f;
  CaptureDrain drain(f.queue, f.sink, f.counters);
  drain.stop(milliseconds(0));
  EXPECT_EQ(f.sink.closes, 1);
  EXPECT_FALSE(f.queue.tryPush(frameWithId(1)));
}

}  // namespace
}  // namespace llmfw
