#include <gtest/gtest.h>

#include <thread>
#include <vector>

#include "capture.pb.h"
#include "llmfw/counters.hpp"

namespace llmfw {
namespace {

TEST(ProxyCounters, SnapshotCopiesEveryCounter) {
  ProxyCounters counters;
  counters.connections_accepted = 3;
  counters.captures_dropped_queue_full = 4;
  counters.tunnels_scoped_no_cert = 5;
  counters.non_connect_requests_rejected = 6;
  (void)counters.nextCaptureId();
  counters.observeQueueDepth(9);
  counters.observeQueueDepth(2);

  llmfw::v1::ProxyStats stats;
  counters.snapshotInto(stats, "instance-1");
  EXPECT_EQ(stats.proxy_instance_id(), "instance-1");
  EXPECT_GT(stats.as_of_unix_ms(), 0);
  EXPECT_EQ(stats.connections_accepted(), 3u);
  EXPECT_EQ(stats.captures_created(), 1u);
  EXPECT_EQ(stats.captures_dropped_queue_full(), 4u);
  EXPECT_EQ(stats.tunnels_scoped_no_cert(), 5u);
  EXPECT_EQ(stats.non_connect_requests_rejected(), 6u);
  EXPECT_EQ(stats.queue_high_watermark_items(), 9u);
}

TEST(ProxyCounters, CaptureIdsStartAtOneAndNeverRepeat) {
  ProxyCounters counters;
  constexpr int kThreads = 8;
  constexpr int kPerThread = 1000;
  std::vector<std::vector<std::uint64_t>> ids(kThreads);
  std::vector<std::thread> threads;
  for (int t = 0; t < kThreads; ++t) {
    threads.emplace_back([&, t] {
      for (int i = 0; i < kPerThread; ++i) {
        ids[static_cast<std::size_t>(t)].push_back(counters.nextCaptureId());
      }
    });
  }
  for (std::thread& t : threads) {
    t.join();
  }
  std::vector<bool> seen(kThreads * kPerThread + 1, false);
  for (const auto& per_thread : ids) {
    for (const std::uint64_t id : per_thread) {
      ASSERT_GE(id, 1u);
      ASSERT_LE(id, static_cast<std::uint64_t>(kThreads * kPerThread));
      ASSERT_FALSE(seen[id]) << "id handed out twice: " << id;
      seen[id] = true;
    }
  }
  EXPECT_EQ(counters.captures_created.load(), static_cast<std::uint64_t>(kThreads * kPerThread));
}

TEST(ProxyCounters, HighWatermarkOnlyRises) {
  ProxyCounters counters;
  counters.observeQueueDepth(5);
  counters.observeQueueDepth(3);
  counters.observeQueueDepth(7);
  EXPECT_EQ(counters.queue_high_watermark_items.load(), 7u);
}

}  // namespace
}  // namespace llmfw
