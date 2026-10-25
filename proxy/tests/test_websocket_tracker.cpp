#include <gtest/gtest.h>

#include <array>
#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "llmfw/websocket_tracker.hpp"

namespace llmfw {
namespace {

using Bytes = std::vector<std::uint8_t>;

/// One unfragmented frame with a payload shorter than 126 bytes.
Bytes frame(std::uint8_t opcode, const std::string& payload, bool masked) {
  constexpr std::array<std::uint8_t, 4> kMask{0x11, 0x22, 0x33, 0x44};
  Bytes out{static_cast<std::uint8_t>(0x80 | opcode),
            static_cast<std::uint8_t>((masked ? 0x80 : 0) | payload.size())};
  if (masked) {
    out.insert(out.end(), kMask.begin(), kMask.end());
  }
  for (std::size_t i = 0; i < payload.size(); ++i) {
    const auto byte = static_cast<std::uint8_t>(payload[i]);
    out.push_back(masked ? static_cast<std::uint8_t>(byte ^ kMask[i % 4]) : byte);
  }
  return out;
}

Bytes clientText(const std::string& payload) { return frame(ws_opcode::kText, payload, true); }
Bytes serverText(const std::string& payload) { return frame(ws_opcode::kText, payload, false); }

/// A tracker over one fake upgraded connection, recording what it pushes.
struct WsFixture {
  explicit WsFixture(CaptureMode mode = CaptureMode::kMetadataOnly, std::size_t cap = 1024) {
    cfg.websocket_message_cap_bytes = cap;
    WebSocketConnection connection;
    connection.connection_id = 9;
    connection.exchange_index = 1;
    connection.upgrade_capture_id = 31;
    connection.host = "api.anthropic.com";
    connection.target = "/v1/ws";
    connection.user_agent = "claude-cli/2";
    tracker = std::make_unique<WebSocketTracker>(
        ctx, cfg, mode, connection,
        WebSocketSinks{[this](std::unique_ptr<llmfw::v1::Frame> frame) { pushed.push_back(std::move(frame)); },
                       [this] { ++decode_errors; }});
  }

  void client(const Bytes& bytes) { tracker->onClientBytes(bytes, Clock::now()); }
  void upstream(const Bytes& bytes) { tracker->onUpstreamBytes(bytes, Clock::now()); }
  [[nodiscard]] const llmfw::v1::WebSocketMessage& ws(std::size_t i) const {
    return pushed.at(i)->capture().websocket();
  }

  ClientClassifier classifier{{{ClientPathTag::kClaudeCode, {"claude-cli/"}}}};
  ProxyCounters counters;
  CaptureBuildContext ctx{classifier, counters};
  CaptureConfig cfg;
  std::unique_ptr<WebSocketTracker> tracker;
  std::vector<std::unique_ptr<llmfw::v1::Frame>> pushed;
  int decode_errors = 0;
};

TEST(WebSocketTracker, RecordsEachMessageWithAnIndexPerDirection) {
  WsFixture f;
  const auto before = std::chrono::system_clock::now();
  f.client(clientText("hello"));
  f.upstream(serverText("one"));
  f.upstream(serverText("two"));
  f.client(clientText("bye"));

  ASSERT_EQ(f.pushed.size(), 4u);
  const llmfw::v1::Capture& first = f.pushed[0]->capture();
  EXPECT_EQ(first.connection_id(), 9u);
  EXPECT_EQ(first.exchange_index(), 1u);
  EXPECT_EQ(first.client().path(), llmfw::v1::CLIENT_PATH_CLAUDE_CODE);
  EXPECT_GE(first.timings().start_unix_us(),
            std::chrono::duration_cast<std::chrono::microseconds>(before.time_since_epoch()).count() - 1000);
  EXPECT_EQ(f.ws(0).upgrade_capture_id(), 31u);
  EXPECT_EQ(f.ws(0).target(), "/v1/ws");

  const std::vector<std::pair<llmfw::v1::Direction, std::uint32_t>> expected = {
      {llmfw::v1::DIRECTION_CLIENT_TO_SERVER, 0},
      {llmfw::v1::DIRECTION_SERVER_TO_CLIENT, 0},
      {llmfw::v1::DIRECTION_SERVER_TO_CLIENT, 1},
      {llmfw::v1::DIRECTION_CLIENT_TO_SERVER, 1},
  };
  for (std::size_t i = 0; i < expected.size(); ++i) {
    EXPECT_EQ(f.ws(i).direction(), expected[i].first) << i;
    EXPECT_EQ(f.ws(i).message_index(), expected[i].second) << i;
  }
  EXPECT_EQ(f.ws(0).total_bytes(), 5u);
  EXPECT_TRUE(f.ws(0).omitted());
  EXPECT_EQ(f.decode_errors, 0);
}

TEST(WebSocketTracker, FullModeKeepsTheCappedPayload) {
  WsFixture f(CaptureMode::kFull, 4);
  f.client(clientText("abcdef"));
  ASSERT_EQ(f.pushed.size(), 1u);
  EXPECT_EQ(f.ws(0).payload(), "abcd");
  EXPECT_EQ(f.ws(0).total_bytes(), 6u);
  EXPECT_TRUE(f.ws(0).truncated());
}

TEST(WebSocketTracker, AProtocolErrorStopsOnlyThatDirection) {
  WsFixture f;
  f.client(frame(ws_opcode::kText, "unmasked", false));
  EXPECT_EQ(f.decode_errors, 1);
  f.client(clientText("ignored"));
  EXPECT_EQ(f.decode_errors, 1) << "counted once per direction";
  f.upstream(serverText("still recorded"));
  ASSERT_EQ(f.pushed.size(), 1u);
  EXPECT_EQ(f.ws(0).direction(), llmfw::v1::DIRECTION_SERVER_TO_CLIENT);
}

TEST(WebSocketTracker, RecordsAMessageOnlyOnceItIsComplete) {
  WsFixture f;
  const Bytes wire = serverText("split message");
  f.upstream(Bytes(wire.begin(), wire.begin() + 5));
  EXPECT_TRUE(f.pushed.empty());
  f.upstream(Bytes(wire.begin() + 5, wire.end()));
  ASSERT_EQ(f.pushed.size(), 1u);
  EXPECT_EQ(f.ws(0).total_bytes(), 13u);
}

}  // namespace
}  // namespace llmfw
