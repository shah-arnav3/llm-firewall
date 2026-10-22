#include <gtest/gtest.h>

#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include "llmfw/http1_parser.hpp"

namespace llmfw {
namespace {

struct Message {
  Http1Head head;
  std::string body;
  bool complete = false;
};

/// Records every event as messages, in order.
class Recorder : public Http1Events {
 public:
  void onHead(const Http1Head& head) override { messages.push_back({head, {}, false}); }
  void onBody(std::span<const std::uint8_t> bytes) override {
    messages.back().body.append(reinterpret_cast<const char*>(bytes.data()), bytes.size());
  }
  void onMessageComplete() override { messages.back().complete = true; }

  std::vector<Message> messages;
};

std::span<const std::uint8_t> bytesOf(std::string_view text) {
  return {reinterpret_cast<const std::uint8_t*>(text.data()), text.size()};
}

FeedResult feedAll(Http1Parser& parser, std::string_view text) { return parser.feed(bytesOf(text)); }

/// Feeds one byte per call and returns the first result that is not kOk (or kOk).
FeedResult feedBytewise(Http1Parser& parser, std::string_view text) {
  for (std::size_t i = 0; i < text.size(); ++i) {
    FeedResult result = parser.feed(bytesOf(text.substr(i, 1)));
    if (result.status != FeedStatus::kOk) {
      result.consumed += i;
      return result;
    }
  }
  return {FeedStatus::kOk, text.size(), {}};
}

constexpr std::string_view kPostWithBody =
    "POST /api/organizations/o1/chat_conversations/c1/completion HTTP/1.1\r\n"
    "Host: claude.ai\r\n"
    "Content-Type: application/json\r\n"
    "Content-Length: 13\r\n"
    "\r\n"
    "{\"prompt\":42}";

TEST(Http1Parser, ParsesRequestHeadAndContentLengthBody) {
  Recorder events;
  Http1Parser parser(Http1Mode::kRequest, events);
  const FeedResult result = feedAll(parser, kPostWithBody);
  EXPECT_EQ(result.status, FeedStatus::kOk);
  EXPECT_EQ(result.consumed, kPostWithBody.size());
  ASSERT_EQ(events.messages.size(), 1u);
  const Message& m = events.messages[0];
  EXPECT_EQ(m.head.method, "POST");
  EXPECT_EQ(m.head.target, "/api/organizations/o1/chat_conversations/c1/completion");
  EXPECT_EQ(m.head.version_major, 1u);
  EXPECT_EQ(m.head.version_minor, 1u);
  EXPECT_EQ(m.head.content_length, 13u);
  EXPECT_FALSE(m.head.chunked);
  EXPECT_TRUE(m.head.keep_alive);
  EXPECT_FALSE(m.head.upgrade);
  EXPECT_EQ(m.body, "{\"prompt\":42}");
  EXPECT_TRUE(m.complete);
}

TEST(Http1Parser, DechunksChunkedBody) {
  Recorder events;
  Http1Parser parser(Http1Mode::kResponse, events);
  const std::string_view wire =
      "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
      "5\r\nhello\r\n7;ext=1\r\n, world\r\n0\r\nTrailer: x\r\n\r\n";
  EXPECT_EQ(feedAll(parser, wire).status, FeedStatus::kOk);
  ASSERT_EQ(events.messages.size(), 1u);
  EXPECT_EQ(events.messages[0].head.status, 200u);
  EXPECT_EQ(events.messages[0].head.reason, "OK");
  EXPECT_TRUE(events.messages[0].head.chunked);
  EXPECT_FALSE(events.messages[0].head.content_length.has_value());
  EXPECT_EQ(events.messages[0].body, "hello, world");
  EXPECT_TRUE(events.messages[0].complete);
}

TEST(Http1Parser, ByteAtATimeFeedingMatchesSingleFeed) {
  const std::string wire = std::string(kPostWithBody) +
                           "GET /a?b=c HTTP/1.1\r\nHost: claude.ai\r\nX-Long-Header-Name: some value\r\n"
                           "Transfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n";
  Recorder whole;
  Http1Parser whole_parser(Http1Mode::kRequest, whole);
  ASSERT_EQ(feedAll(whole_parser, wire).status, FeedStatus::kOk);
  Recorder split;
  Http1Parser split_parser(Http1Mode::kRequest, split);
  ASSERT_EQ(feedBytewise(split_parser, wire).status, FeedStatus::kOk);

  ASSERT_EQ(split.messages.size(), whole.messages.size());
  for (std::size_t i = 0; i < whole.messages.size(); ++i) {
    EXPECT_EQ(split.messages[i].head.method, whole.messages[i].head.method);
    EXPECT_EQ(split.messages[i].head.target, whole.messages[i].head.target);
    EXPECT_EQ(split.messages[i].head.headers, whole.messages[i].head.headers);
    EXPECT_EQ(split.messages[i].body, whole.messages[i].body);
    EXPECT_TRUE(split.messages[i].complete);
  }
}

TEST(Http1Parser, PreservesHeaderOrderCaseAndDuplicates) {
  Recorder events;
  Http1Parser parser(Http1Mode::kRequest, events);
  ASSERT_EQ(feedAll(parser, "GET / HTTP/1.1\r\nhost: claude.ai\r\nAccept: a\r\nX-Empty:\r\nACCEPT: b\r\n"
                            "Cookie: s=1\r\n\r\n")
                .status,
            FeedStatus::kOk);
  ASSERT_EQ(events.messages.size(), 1u);
  const std::vector<std::pair<std::string, std::string>> expected{
      {"host", "claude.ai"}, {"Accept", "a"}, {"X-Empty", ""}, {"ACCEPT", "b"}, {"Cookie", "s=1"}};
  EXPECT_EQ(events.messages[0].head.headers, expected);
}

TEST(Http1Parser, HandlesPipelinedRequests) {
  Recorder events;
  Http1Parser parser(Http1Mode::kRequest, events);
  ASSERT_EQ(feedAll(parser, "GET /1 HTTP/1.1\r\nHost: a\r\n\r\nHEAD /2 HTTP/1.1\r\nHost: a\r\n\r\n"
                            "DELETE /3 HTTP/1.1\r\nHost: a\r\nContent-Length: 1\r\n\r\nx")
                .status,
            FeedStatus::kOk);
  ASSERT_EQ(events.messages.size(), 3u);
  EXPECT_EQ(events.messages[0].head.method, "GET");
  EXPECT_EQ(events.messages[1].head.method, "HEAD");
  EXPECT_EQ(events.messages[2].head.method, "DELETE");
  EXPECT_EQ(events.messages[2].body, "x");
  for (const Message& m : events.messages) {
    EXPECT_TRUE(m.complete);
  }
}

TEST(Http1Parser, HeadResponseHasNoBody) {
  Recorder events;
  Http1Parser parser(Http1Mode::kResponse, events);
  parser.expectResponse(false);
  parser.expectResponse(true);
  parser.expectResponse(false);
  ASSERT_EQ(feedAll(parser, "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nfirst"
                            "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n"
                            "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nthird")
                .status,
            FeedStatus::kOk);
  ASSERT_EQ(events.messages.size(), 3u);
  EXPECT_EQ(events.messages[0].body, "first");
  EXPECT_EQ(events.messages[1].body, "");
  EXPECT_TRUE(events.messages[1].complete);
  EXPECT_EQ(events.messages[1].head.content_length, 5u);
  EXPECT_EQ(events.messages[2].body, "third");
}

TEST(Http1Parser, InterimResponseDoesNotAnswerTheRequest) {
  Recorder events;
  Http1Parser parser(Http1Mode::kResponse, events);
  parser.expectResponse(true);
  ASSERT_EQ(feedAll(parser, "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n").status,
            FeedStatus::kOk);
  ASSERT_EQ(events.messages.size(), 2u);
  EXPECT_EQ(events.messages[0].head.status, 100u);
  EXPECT_EQ(events.messages[1].head.status, 200u);
  EXPECT_TRUE(events.messages[1].complete);  // The HEAD answer: no body despite Content-Length.
}

TEST(Http1Parser, SseResponseStreamsBodyUntilClose) {
  Recorder events;
  Http1Parser parser(Http1Mode::kResponse, events);
  ASSERT_EQ(feedAll(parser, "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n"
                            "event: message_start\ndata: {}\n\n")
                .status,
            FeedStatus::kOk);
  ASSERT_EQ(feedAll(parser, "event: message_stop\ndata: {}\n\n").status, FeedStatus::kOk);
  ASSERT_EQ(events.messages.size(), 1u);
  EXPECT_FALSE(events.messages[0].complete);
  EXPECT_EQ(parser.finish().status, FeedStatus::kOk);
  EXPECT_TRUE(events.messages[0].complete);
  EXPECT_EQ(events.messages[0].body, "event: message_start\ndata: {}\n\nevent: message_stop\ndata: {}\n\n");
}

TEST(Http1Parser, EofInsideAKnownLengthBodyIsAnError) {
  Recorder events;
  Http1Parser parser(Http1Mode::kResponse, events);
  ASSERT_EQ(feedAll(parser, "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc").status, FeedStatus::kOk);
  EXPECT_EQ(parser.finish().status, FeedStatus::kError);
  EXPECT_FALSE(events.messages[0].complete);
}

TEST(Http1Parser, UpgradeReportsConsumedOffset) {
  Recorder events;
  Http1Parser parser(Http1Mode::kResponse, events);
  parser.expectResponse(false);
  const std::string_view head =
      "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n";
  const std::string wire = std::string(head) + "\x81\x02hi";
  const FeedResult result = feedAll(parser, wire);
  EXPECT_EQ(result.status, FeedStatus::kUpgrade);
  EXPECT_EQ(result.consumed, head.size());
  ASSERT_EQ(events.messages.size(), 1u);
  EXPECT_TRUE(events.messages[0].head.upgrade);
  EXPECT_EQ(events.messages[0].body, "");

  const FeedResult again = feedAll(parser, "more");
  EXPECT_EQ(again.status, FeedStatus::kUpgrade);
  EXPECT_EQ(again.consumed, 0u);
}

TEST(Http1Parser, RejectedUpgradeRequestResumesParsing) {
  Recorder events;
  Http1Parser parser(Http1Mode::kRequest, events);
  const std::string_view upgrade =
      "GET /ws HTTP/1.1\r\nHost: claude.ai\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n";
  const FeedResult result = feedAll(parser, upgrade);
  ASSERT_EQ(result.status, FeedStatus::kUpgrade);
  EXPECT_EQ(result.consumed, upgrade.size());
  EXPECT_TRUE(events.messages[0].head.upgrade);

  parser.resumeAfterRejectedUpgrade();
  EXPECT_EQ(feedAll(parser, "GET /next HTTP/1.1\r\nHost: claude.ai\r\n\r\n").status, FeedStatus::kOk);
  ASSERT_EQ(events.messages.size(), 2u);
  EXPECT_EQ(events.messages[1].head.target, "/next");
}

TEST(Http1Parser, RejectsOversizeHead) {
  Recorder events;
  Http1Parser parser(Http1Mode::kRequest, events, Http1Limits{64, 256});
  const FeedResult result = feedAll(parser, "GET / HTTP/1.1\r\nX-Big: " + std::string(100, 'a') + "\r\n\r\n");
  EXPECT_EQ(result.status, FeedStatus::kError);
  EXPECT_NE(result.error.find("max_head_bytes"), std::string::npos) << result.error;
  EXPECT_TRUE(events.messages.empty());
}

TEST(Http1Parser, LimitsApplyPerMessage) {
  Recorder events;
  Http1Parser parser(Http1Mode::kRequest, events, Http1Limits{64, 2});
  const std::string one = "GET /x HTTP/1.1\r\nHost: a\r\nX-A: " + std::string(30, 'a') + "\r\n\r\n";
  EXPECT_EQ(feedAll(parser, one + one + one).status, FeedStatus::kOk);
  EXPECT_EQ(events.messages.size(), 3u);
}

TEST(Http1Parser, RejectsTooManyHeaders) {
  Recorder events;
  Http1Parser parser(Http1Mode::kRequest, events, Http1Limits{64 * 1024, 2});
  const FeedResult result = feedAll(parser, "GET / HTTP/1.1\r\nA: 1\r\nB: 2\r\nC: 3\r\n\r\n");
  EXPECT_EQ(result.status, FeedStatus::kError);
  EXPECT_NE(result.error.find("too many headers"), std::string::npos) << result.error;
}

TEST(Http1Parser, RejectsConflictingContentLengthAndChunked) {
  Recorder events;
  Http1Parser parser(Http1Mode::kRequest, events);
  const FeedResult result = feedAll(
      parser, "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n");
  EXPECT_EQ(result.status, FeedStatus::kError);
  EXPECT_TRUE(events.messages.empty());
}

TEST(Http1Parser, ErrorMessageContainsNoPayloadBytes) {
  Recorder events;
  Http1Parser parser(Http1Mode::kRequest, events);
  const FeedResult result = feedAll(parser, "GET / HTTP/1.1\r\nAuthorization: Bearer sk-secret-token\x01\r\n\r\n");
  ASSERT_EQ(result.status, FeedStatus::kError);
  EXPECT_FALSE(result.error.empty());
  EXPECT_EQ(result.error.find("secret"), std::string::npos) << result.error;
  EXPECT_EQ(result.error.find("Bearer"), std::string::npos) << result.error;
}

TEST(Http1Parser, StaysFailedAfterAnError) {
  Recorder events;
  Http1Parser parser(Http1Mode::kRequest, events);
  const FeedResult first = feedAll(parser, "NOT HTTP AT ALL\r\n\r\n");
  ASSERT_EQ(first.status, FeedStatus::kError);
  const FeedResult second = feedAll(parser, "GET / HTTP/1.1\r\nHost: a\r\n\r\n");
  EXPECT_EQ(second.status, FeedStatus::kError);
  EXPECT_EQ(second.consumed, 0u);
  EXPECT_EQ(second.error, first.error);
  EXPECT_EQ(parser.finish().status, FeedStatus::kError);
  EXPECT_TRUE(events.messages.empty());
}

/// Throws from onBody.
class ThrowingEvents : public Recorder {
 public:
  void onBody(std::span<const std::uint8_t> /*bytes*/) override { throw std::runtime_error("full"); }
};

TEST(Http1Parser, AThrowingHandlerStopsTheParse) {
  ThrowingEvents events;
  Http1Parser parser(Http1Mode::kRequest, events);
  const FeedResult result = feedAll(parser, kPostWithBody);
  EXPECT_EQ(result.status, FeedStatus::kError);
  EXPECT_NE(result.error.find("event handler threw"), std::string::npos) << result.error;
}

}  // namespace
}  // namespace llmfw
