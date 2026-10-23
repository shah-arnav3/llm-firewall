#include <gtest/gtest.h>

#include <chrono>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "llmfw/http1_exchange_tracker.hpp"

namespace llmfw {
namespace {

using std::chrono::milliseconds;

std::span<const std::uint8_t> bytesOf(std::string_view text) {
  return {reinterpret_cast<const std::uint8_t*>(text.data()), text.size()};
}

/// A tracker over one fake connection, recording what it pushes.
struct TrackerFixture {
  ClientClassifier classifier{{{ClientPathTag::kClaudeCode, {"claude-cli/"}}}};
  ProxyCounters counters;
  CaptureBuildContext ctx{classifier, counters};
  CaptureConfig cfg;
  ExchangeConnection connection{7, "api.anthropic.com", 443, "", "", {}, {}};
  std::vector<std::unique_ptr<llmfw::v1::Frame>> pushed;
  int parse_errors = 0;
  Http1ExchangeTracker tracker{ctx, cfg, CaptureMode::kMetadataOnly, connection,
                               ExchangeSinks{[this](std::unique_ptr<llmfw::v1::Frame> frame) {
                                               pushed.push_back(std::move(frame));
                                             },
                                             [this] { ++parse_errors; }}};
  Clock::time_point t0 = Clock::now();

  void client(std::string_view text, milliseconds after = {}) { tracker.onClientBytes(bytesOf(text), t0 + after); }
  void upstream(std::string_view text, milliseconds after = {}) { tracker.onUpstreamBytes(bytesOf(text), t0 + after); }
  [[nodiscard]] const llmfw::v1::HttpExchange& http(std::size_t i) const { return pushed.at(i)->capture().http(); }
};

constexpr std::string_view kGet = "GET /v1/models HTTP/1.1\r\nHost: api.anthropic.com\r\nUser-Agent: claude-cli/2\r\n\r\n";
constexpr std::string_view kOk = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";

TEST(Http1ExchangeTracker, PushesACompleteExchangeWithTimings) {
  TrackerFixture f;
  f.client("POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\nUser-Agent: claude-cli/2\r\n"
           "Content-Length: 4\r\n\r\nab");
  f.client("cd", milliseconds(2));
  EXPECT_TRUE(f.pushed.empty());
  f.upstream("HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nabc", milliseconds(300));
  f.upstream("def", milliseconds(900));

  ASSERT_EQ(f.pushed.size(), 1u);
  const llmfw::v1::Capture& capture = f.pushed[0]->capture();
  EXPECT_EQ(capture.connection_id(), 7u);
  EXPECT_EQ(capture.exchange_index(), 0u);
  EXPECT_EQ(capture.client().path(), llmfw::v1::CLIENT_PATH_CLAUDE_CODE);
  EXPECT_EQ(f.http(0).outcome(), llmfw::v1::EXCHANGE_OUTCOME_COMPLETE);
  EXPECT_EQ(f.http(0).request().method(), "POST");
  EXPECT_EQ(f.http(0).request().body().total_bytes(), 4u);
  EXPECT_EQ(f.http(0).response().status(), 200u);
  EXPECT_EQ(f.http(0).response().body().total_bytes(), 6u);
  EXPECT_EQ(capture.timings().request_complete_us(), 2'000u);
  EXPECT_EQ(capture.timings().response_first_byte_us(), 300'000u);
  EXPECT_EQ(capture.timings().response_complete_us(), 900'000u);
}

TEST(Http1ExchangeTracker, PairsPipelinedRequestsInOrder) {
  TrackerFixture f;
  f.client(std::string(kGet) + "GET /v1/other HTTP/1.1\r\nHost: api.anthropic.com\r\n\r\n");
  f.upstream(std::string(kOk) + "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n");
  ASSERT_EQ(f.pushed.size(), 2u);
  EXPECT_EQ(f.pushed[0]->capture().exchange_index(), 0u);
  EXPECT_EQ(f.http(0).request().target(), "/v1/models");
  EXPECT_EQ(f.http(0).response().status(), 200u);
  EXPECT_EQ(f.pushed[1]->capture().exchange_index(), 1u);
  EXPECT_EQ(f.http(1).request().target(), "/v1/other");
  EXPECT_EQ(f.http(1).response().status(), 404u);
}

TEST(Http1ExchangeTracker, HeadResponseHasNoBody) {
  TrackerFixture f;
  f.client("HEAD /a HTTP/1.1\r\nHost: a\r\n\r\n");
  f.client(kGet);
  f.upstream("HTTP/1.1 200 OK\r\nContent-Length: 50\r\n\r\n");
  f.upstream(kOk);
  ASSERT_EQ(f.pushed.size(), 2u);
  EXPECT_EQ(f.http(0).request().method(), "HEAD");
  EXPECT_EQ(f.http(0).response().body().total_bytes(), 0u);
  EXPECT_EQ(f.http(1).response().body().total_bytes(), 2u);
}

TEST(Http1ExchangeTracker, SkipsInterimResponses) {
  TrackerFixture f;
  f.client(kGet);
  f.upstream("HTTP/1.1 100 Continue\r\n\r\n");
  EXPECT_TRUE(f.pushed.empty());
  f.upstream(kOk);
  ASSERT_EQ(f.pushed.size(), 1u);
  EXPECT_EQ(f.http(0).response().status(), 200u);
}

TEST(Http1ExchangeTracker, ACloseCompletesACloseDelimitedResponse) {
  TrackerFixture f;
  f.client(kGet);
  f.upstream("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\ndata: 1\n\n");
  EXPECT_TRUE(f.pushed.empty());
  f.tracker.onClosed(ExchangeOutcomeTag::kUpstreamAborted);
  ASSERT_EQ(f.pushed.size(), 1u);
  EXPECT_EQ(f.http(0).outcome(), llmfw::v1::EXCHANGE_OUTCOME_COMPLETE);
  EXPECT_EQ(f.http(0).response().body().total_bytes(), 9u);
}

TEST(Http1ExchangeTracker, ACloseFinishesUnansweredExchangesWithTheGivenOutcome) {
  TrackerFixture f;
  f.client(kGet);
  f.client(kGet);
  f.upstream("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc");
  f.tracker.onClosed(ExchangeOutcomeTag::kClientAborted);
  ASSERT_EQ(f.pushed.size(), 2u);
  EXPECT_EQ(f.http(0).outcome(), llmfw::v1::EXCHANGE_OUTCOME_CLIENT_ABORTED);
  EXPECT_EQ(f.http(0).response().body().total_bytes(), 3u);
  EXPECT_EQ(f.http(1).outcome(), llmfw::v1::EXCHANGE_OUTCOME_CLIENT_ABORTED);
  EXPECT_FALSE(f.http(1).has_response());
  EXPECT_EQ(f.parse_errors, 0);
}

TEST(Http1ExchangeTracker, AnEarlyResponseCompletesTheExchange) {
  TrackerFixture f;
  f.client("POST /upload HTTP/1.1\r\nHost: a\r\nContent-Length: 100\r\n\r\nfirst");
  f.upstream("HTTP/1.1 413 Payload Too Large\r\nContent-Length: 0\r\n\r\n");
  ASSERT_EQ(f.pushed.size(), 1u);
  EXPECT_EQ(f.http(0).response().status(), 413u);
  EXPECT_EQ(f.http(0).request().body().total_bytes(), 5u);
  f.client("more body bytes");
  f.tracker.onClosed(ExchangeOutcomeTag::kClientAborted);
  EXPECT_EQ(f.pushed.size(), 1u);
}

TEST(Http1ExchangeTracker, IgnoresAResponseWithNoRequest) {
  TrackerFixture f;
  f.upstream(kOk);
  EXPECT_TRUE(f.pushed.empty());
  f.client(kGet);
  f.upstream(kOk);
  ASSERT_EQ(f.pushed.size(), 1u);
  EXPECT_EQ(f.http(0).request().target(), "/v1/models");
}

TEST(Http1ExchangeTracker, AFramingErrorStopsRecording) {
  TrackerFixture f;
  f.client(kGet);
  f.upstream("NOT HTTP\r\n\r\n");
  ASSERT_EQ(f.pushed.size(), 1u);
  EXPECT_EQ(f.http(0).outcome(), llmfw::v1::EXCHANGE_OUTCOME_PARSE_ERROR);
  EXPECT_EQ(f.parse_errors, 1);
  f.client(kGet);
  f.upstream(kOk);
  f.tracker.onClosed(ExchangeOutcomeTag::kClientAborted);
  EXPECT_EQ(f.pushed.size(), 1u);
  EXPECT_EQ(f.parse_errors, 1);
}

constexpr std::string_view kUpgradeRequest =
    "GET /ws HTTP/1.1\r\nHost: a\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n";

TEST(Http1ExchangeTracker, ASwitchingResponsePushesTheUpgradeAndStopsRecording) {
  TrackerFixture f;
  f.client(kUpgradeRequest);
  EXPECT_TRUE(f.pushed.empty());
  f.upstream("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n\x81\x00");
  ASSERT_EQ(f.pushed.size(), 1u);
  EXPECT_EQ(f.http(0).outcome(), llmfw::v1::EXCHANGE_OUTCOME_UPGRADED);
  EXPECT_EQ(f.http(0).response().status(), 101u);
  f.client("\x81\x80\x00\x00\x00\x00");
  f.upstream(kOk);
  f.tracker.onClosed(ExchangeOutcomeTag::kClientAborted);
  EXPECT_EQ(f.pushed.size(), 1u);
  EXPECT_EQ(f.parse_errors, 0);
}

TEST(Http1ExchangeTracker, ARefusedUpgradeResumesWithTheHeldBytes) {
  TrackerFixture f;
  f.client(std::string(kUpgradeRequest) + "GET /next");
  f.client(" HTTP/1.1\r\nHost: a\r\n\r\n");
  f.upstream("HTTP/1.1 426 Upgrade Required\r\nContent-Length: 0\r\n\r\n");
  ASSERT_EQ(f.pushed.size(), 1u);
  EXPECT_EQ(f.http(0).outcome(), llmfw::v1::EXCHANGE_OUTCOME_COMPLETE);
  EXPECT_EQ(f.http(0).response().status(), 426u);
  f.upstream(kOk);
  ASSERT_EQ(f.pushed.size(), 2u);
  EXPECT_EQ(f.http(1).request().target(), "/next");
  EXPECT_EQ(f.http(1).response().status(), 200u);
}

TEST(Http1ExchangeTracker, TooManyBytesWhileAnUpgradeWaitsIsAFramingError) {
  TrackerFixture f;
  f.client(kUpgradeRequest);
  f.client(std::string(Http1ExchangeTracker::kMaxHeldUpgradeBytes + 1, 'x'));
  ASSERT_EQ(f.pushed.size(), 1u);
  EXPECT_EQ(f.http(0).outcome(), llmfw::v1::EXCHANGE_OUTCOME_PARSE_ERROR);
  EXPECT_EQ(f.parse_errors, 1);
}

TEST(Http1ExchangeTracker, SplitChunksGiveTheSameExchanges) {
  const std::string requests = std::string(kGet) + "POST /b HTTP/1.1\r\nHost: a\r\nContent-Length: 3\r\n\r\nxyz";
  const std::string responses = std::string(kOk) + "HTTP/1.1 201 Created\r\nTransfer-Encoding: chunked\r\n\r\n"
                                                   "2\r\nhi\r\n0\r\n\r\n";
  TrackerFixture f;
  for (std::size_t i = 0; i < requests.size(); ++i) {
    f.client(std::string_view(requests).substr(i, 1));
  }
  for (std::size_t i = 0; i < responses.size(); ++i) {
    f.upstream(std::string_view(responses).substr(i, 1));
  }
  ASSERT_EQ(f.pushed.size(), 2u);
  EXPECT_EQ(f.http(0).response().body().total_bytes(), 2u);
  EXPECT_EQ(f.http(1).request().body().total_bytes(), 3u);
  EXPECT_EQ(f.http(1).response().status(), 201u);
  EXPECT_EQ(f.http(1).response().body().total_bytes(), 2u);
}

}  // namespace
}  // namespace llmfw
