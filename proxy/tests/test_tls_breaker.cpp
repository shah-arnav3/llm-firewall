#include <gtest/gtest.h>

#include <string>
#include <thread>
#include <vector>

#include "llmfw/tls_breaker.hpp"

namespace llmfw {
namespace {

using std::chrono::milliseconds;

const Clock::time_point kT0 = Clock::time_point{} + std::chrono::hours{1};

TEST(ClientTlsBreaker, ClosedForUnknownHosts) {
  const ClientTlsBreaker breaker(milliseconds{1000});
  EXPECT_FALSE(breaker.isOpen("claude.ai", kT0));
}

TEST(ClientTlsBreaker, OpenUntilTheCooldownEnds) {
  ClientTlsBreaker breaker(milliseconds{1000});
  breaker.recordFailure("claude.ai", kT0);
  EXPECT_TRUE(breaker.isOpen("claude.ai", kT0));
  EXPECT_TRUE(breaker.isOpen("claude.ai", kT0 + milliseconds{999}));
  EXPECT_FALSE(breaker.isOpen("claude.ai", kT0 + milliseconds{1000}));
}

TEST(ClientTlsBreaker, OnlyTheFailingHostIsOpen) {
  ClientTlsBreaker breaker(milliseconds{1000});
  breaker.recordFailure("claude.ai", kT0);
  EXPECT_FALSE(breaker.isOpen("api.anthropic.com", kT0));
  EXPECT_FALSE(breaker.isOpen("api.claude.ai", kT0));
}

TEST(ClientTlsBreaker, ALaterFailureExtendsTheWindow) {
  ClientTlsBreaker breaker(milliseconds{1000});
  breaker.recordFailure("claude.ai", kT0);
  breaker.recordFailure("claude.ai", kT0 + milliseconds{800});
  EXPECT_TRUE(breaker.isOpen("claude.ai", kT0 + milliseconds{1500}));
  EXPECT_FALSE(breaker.isOpen("claude.ai", kT0 + milliseconds{1800}));
}

TEST(ClientTlsBreaker, ExpiredHostsArePrunedOnTheNextFailure) {
  ClientTlsBreaker breaker(milliseconds{1000});
  breaker.recordFailure("a.claude.ai", kT0);
  breaker.recordFailure("b.claude.ai", kT0 + milliseconds{2000});
  EXPECT_FALSE(breaker.isOpen("a.claude.ai", kT0 + milliseconds{2000}));
  EXPECT_TRUE(breaker.isOpen("b.claude.ai", kT0 + milliseconds{2000}));
}

TEST(ClientTlsBreaker, ZeroCooldownNeverOpens) {
  ClientTlsBreaker breaker(milliseconds{0});
  breaker.recordFailure("claude.ai", kT0);
  EXPECT_FALSE(breaker.isOpen("claude.ai", kT0));
}

// Run under TSan to check the locking.
TEST(ClientTlsBreaker, ConcurrentUseIsSafe) {
  ClientTlsBreaker breaker(milliseconds{50});
  std::vector<std::thread> threads;
  for (int t = 0; t < 8; ++t) {
    threads.emplace_back([&breaker, t] {
      for (int i = 0; i < 2000; ++i) {
        const std::string host = "h" + std::to_string((t * 7 + i) % 64) + ".claude.ai";
        const Clock::time_point now = kT0 + milliseconds{i};
        if (i % 3 == 0) {
          breaker.recordFailure(host, now);
        } else {
          (void)breaker.isOpen(host, now);
        }
      }
    });
  }
  for (std::thread& thread : threads) {
    thread.join();
  }
  // Still usable afterwards: a new failure opens, and the old windows have all expired.
  breaker.recordFailure("done.claude.ai", kT0 + std::chrono::seconds{10});
  EXPECT_TRUE(breaker.isOpen("done.claude.ai", kT0 + std::chrono::seconds{10}));
  EXPECT_FALSE(breaker.isOpen("h0.claude.ai", kT0 + std::chrono::seconds{10}));
}

}  // namespace
}  // namespace llmfw
