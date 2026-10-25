#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "llmfw/websocket.hpp"

namespace llmfw {
namespace {

using Bytes = std::vector<std::uint8_t>;

constexpr std::array<std::uint8_t, 4> kMask{0x37, 0xfa, 0x21, 0x3d};

struct FrameSpec {
  std::uint8_t opcode = ws_opcode::kText;
  std::string payload;
  bool fin = true;
  bool rsv1 = false;
  bool masked = false;
};

/// Encodes one frame the way a sender would, with the shortest length form.
Bytes frame(const FrameSpec& spec) {
  Bytes out;
  out.push_back(static_cast<std::uint8_t>((spec.fin ? 0x80 : 0) | (spec.rsv1 ? 0x40 : 0) | spec.opcode));
  const std::uint8_t mask_bit = spec.masked ? 0x80 : 0;
  const std::uint64_t n = spec.payload.size();
  if (n < 126) {
    out.push_back(static_cast<std::uint8_t>(mask_bit | n));
  } else if (n <= 0xFFFF) {
    out.push_back(mask_bit | 126);
    out.push_back(static_cast<std::uint8_t>(n >> 8));
    out.push_back(static_cast<std::uint8_t>(n));
  } else {
    out.push_back(mask_bit | 127);
    for (int shift = 56; shift >= 0; shift -= 8) {
      out.push_back(static_cast<std::uint8_t>(n >> shift));
    }
  }
  if (spec.masked) {
    out.insert(out.end(), kMask.begin(), kMask.end());
  }
  for (std::size_t i = 0; i < spec.payload.size(); ++i) {
    const auto byte = static_cast<std::uint8_t>(spec.payload[i]);
    out.push_back(spec.masked ? static_cast<std::uint8_t>(byte ^ kMask[i % 4]) : byte);
  }
  return out;
}

Bytes concat(std::initializer_list<Bytes> parts) {
  Bytes out;
  for (const Bytes& part : parts) {
    out.insert(out.end(), part.begin(), part.end());
  }
  return out;
}

std::string text(const WsMessage& message) { return {message.payload.begin(), message.payload.end()}; }

/// A decoder plus the messages it has delivered.
struct Decoded {
  explicit Decoded(WsSender sender, std::size_t cap = 1024) : decoder(sender, cap) {}

  WsDecodeResult feed(const Bytes& wire) {
    return decoder.feed(wire, [this](WsMessage&& message) { messages.push_back(std::move(message)); });
  }

  WebSocketFrameDecoder decoder;
  std::vector<WsMessage> messages;
};

TEST(WebSocketFrameDecoder, DecodesAServerTextFrame) {
  Decoded d(WsSender::kServer);
  EXPECT_EQ(d.feed(frame({.payload = "hello"})).status, WsDecodeStatus::kOk);
  ASSERT_EQ(d.messages.size(), 1u);
  EXPECT_EQ(d.messages[0].opcode, ws_opcode::kText);
  EXPECT_EQ(text(d.messages[0]), "hello");
  EXPECT_EQ(d.messages[0].total_bytes, 5u);
  EXPECT_FALSE(d.messages[0].truncated);
  EXPECT_FALSE(d.messages[0].compressed);
}

TEST(WebSocketFrameDecoder, UnmasksAClientFrameWithoutChangingTheInput) {
  Decoded d(WsSender::kClient);
  const Bytes wire = frame({.payload = "secret", .masked = true});
  const Bytes before = wire;
  EXPECT_EQ(d.feed(wire).status, WsDecodeStatus::kOk);
  ASSERT_EQ(d.messages.size(), 1u);
  EXPECT_EQ(text(d.messages[0]), "secret");
  EXPECT_EQ(wire, before);
}

TEST(WebSocketFrameDecoder, JoinsAFragmentedMessage) {
  Decoded d(WsSender::kClient);
  EXPECT_EQ(d.feed(concat({frame({.opcode = ws_opcode::kBinary, .payload = "ab", .fin = false, .masked = true}),
                           frame({.opcode = ws_opcode::kContinuation, .payload = "cd", .fin = false, .masked = true}),
                           frame({.opcode = ws_opcode::kContinuation, .payload = "e", .masked = true})}))
                .status,
            WsDecodeStatus::kOk);
  ASSERT_EQ(d.messages.size(), 1u);
  EXPECT_EQ(d.messages[0].opcode, ws_opcode::kBinary);
  EXPECT_EQ(text(d.messages[0]), "abcde");
}

TEST(WebSocketFrameDecoder, DeliversAControlFrameBetweenFragmentsFirst) {
  Decoded d(WsSender::kServer);
  EXPECT_EQ(d.feed(concat({frame({.payload = "one ", .fin = false}),
                           frame({.opcode = ws_opcode::kPing, .payload = "p"}),
                           frame({.opcode = ws_opcode::kContinuation, .payload = "two"})}))
                .status,
            WsDecodeStatus::kOk);
  ASSERT_EQ(d.messages.size(), 2u);
  EXPECT_EQ(d.messages[0].opcode, ws_opcode::kPing);
  EXPECT_EQ(text(d.messages[0]), "p");
  EXPECT_EQ(d.messages[1].opcode, ws_opcode::kText);
  EXPECT_EQ(text(d.messages[1]), "one two");
}

TEST(WebSocketFrameDecoder, ReadsSixteenAndSixtyFourBitLengths) {
  Decoded d(WsSender::kClient, 1 << 20);
  const std::string medium(300, 'm');
  const std::string large(70'000, 'L');
  EXPECT_EQ(d.feed(concat({frame({.payload = medium, .masked = true}), frame({.payload = large, .masked = true})}))
                .status,
            WsDecodeStatus::kOk);
  ASSERT_EQ(d.messages.size(), 2u);
  EXPECT_EQ(text(d.messages[0]), medium);
  EXPECT_EQ(text(d.messages[1]), large);
}

TEST(WebSocketFrameDecoder, AnyChunkingGivesTheSameMessages) {
  const Bytes wire = concat({frame({.payload = "first", .fin = false, .masked = true}),
                             frame({.opcode = ws_opcode::kPong, .masked = true}),
                             frame({.opcode = ws_opcode::kContinuation, .payload = std::string(200, 'x'),
                                    .masked = true}),
                             frame({.opcode = ws_opcode::kClose, .payload = "\x03\xe8", .masked = true})});
  Decoded whole(WsSender::kClient);
  ASSERT_EQ(whole.feed(wire).status, WsDecodeStatus::kOk);
  ASSERT_EQ(whole.messages.size(), 3u);
  for (const std::size_t chunk : {1u, 2u, 3u, 7u, 64u}) {
    Decoded split(WsSender::kClient);
    for (std::size_t pos = 0; pos < wire.size(); pos += chunk) {
      const std::span<const std::uint8_t> piece = std::span(wire).subspan(pos, std::min(chunk, wire.size() - pos));
      ASSERT_EQ(split.feed(Bytes(piece.begin(), piece.end())).status, WsDecodeStatus::kOk);
    }
    ASSERT_EQ(split.messages.size(), whole.messages.size()) << "chunk " << chunk;
    for (std::size_t i = 0; i < whole.messages.size(); ++i) {
      EXPECT_EQ(split.messages[i].opcode, whole.messages[i].opcode) << "chunk " << chunk;
      EXPECT_EQ(split.messages[i].payload, whole.messages[i].payload) << "chunk " << chunk;
    }
  }
}

TEST(WebSocketFrameDecoder, CapsThePayloadAndMarksItTruncated) {
  Decoded d(WsSender::kClient, 4);
  EXPECT_EQ(d.feed(concat({frame({.payload = "abc", .fin = false, .masked = true}),
                           frame({.opcode = ws_opcode::kContinuation, .payload = "defg", .masked = true})}))
                .status,
            WsDecodeStatus::kOk);
  ASSERT_EQ(d.messages.size(), 1u);
  EXPECT_EQ(text(d.messages[0]), "abcd") << "unmasked across the frame boundary";
  EXPECT_EQ(d.messages[0].total_bytes, 7u);
  EXPECT_TRUE(d.messages[0].truncated);
}

TEST(WebSocketFrameDecoder, FlagsRsv1AsCompressed) {
  Decoded d(WsSender::kServer);
  EXPECT_EQ(d.feed(concat({frame({.payload = "z", .fin = false, .rsv1 = true}),
                           frame({.opcode = ws_opcode::kContinuation, .payload = "z"})}))
                .status,
            WsDecodeStatus::kOk);
  ASSERT_EQ(d.messages.size(), 1u);
  EXPECT_TRUE(d.messages[0].compressed);
}

TEST(WebSocketFrameDecoder, DeliversEmptyFrames) {
  Decoded d(WsSender::kServer);
  EXPECT_EQ(d.feed(concat({frame({}), frame({.opcode = ws_opcode::kPing})})).status, WsDecodeStatus::kOk);
  ASSERT_EQ(d.messages.size(), 2u);
  EXPECT_EQ(d.messages[0].total_bytes, 0u);
  EXPECT_EQ(d.messages[1].opcode, ws_opcode::kPing);
}

struct Violation {
  std::string_view name;
  WsSender sender;
  Bytes wire;
};

TEST(WebSocketFrameDecoder, RejectsProtocolViolations) {
  Bytes rsv2 = frame({.payload = "x"});
  rsv2[0] |= 0x20;
  Bytes huge_length = {0x82, 127, 0x80, 0, 0, 0, 0, 0, 0, 1};
  const std::vector<Violation> violations = {
      {"unmasked client frame", WsSender::kClient, frame({.payload = "x"})},
      {"masked server frame", WsSender::kServer, frame({.payload = "x", .masked = true})},
      {"RSV2", WsSender::kServer, rsv2},
      {"RSV1 on a control frame", WsSender::kServer, frame({.opcode = ws_opcode::kPing, .rsv1 = true})},
      {"RSV1 on a continuation", WsSender::kServer,
       concat({frame({.payload = "a", .fin = false}),
               frame({.opcode = ws_opcode::kContinuation, .payload = "b", .rsv1 = true})})},
      {"reserved data opcode", WsSender::kServer, frame({.opcode = 0x3})},
      {"reserved control opcode", WsSender::kServer, frame({.opcode = 0xB})},
      {"fragmented control frame", WsSender::kServer, frame({.opcode = ws_opcode::kPing, .fin = false})},
      {"long control frame", WsSender::kServer, frame({.opcode = ws_opcode::kPing, .payload = std::string(126, 'p')})},
      {"orphan continuation", WsSender::kServer, frame({.opcode = ws_opcode::kContinuation})},
      {"interrupted message", WsSender::kServer, concat({frame({.fin = false}), frame({})})},
      {"64-bit length top bit", WsSender::kServer, huge_length},
      {"frame after close", WsSender::kServer, concat({frame({.opcode = ws_opcode::kClose}), frame({})})},
  };
  for (const Violation& v : violations) {
    Decoded d(v.sender);
    const WsDecodeResult result = d.feed(v.wire);
    EXPECT_EQ(result.status, WsDecodeStatus::kError) << v.name;
    EXPECT_FALSE(result.error.empty()) << v.name;
    const WsDecodeResult again = d.feed(frame({.masked = v.sender == WsSender::kClient}));
    EXPECT_EQ(again.status, WsDecodeStatus::kError) << v.name << ": the error sticks";
    EXPECT_EQ(again.error, result.error) << v.name;
  }
}

}  // namespace
}  // namespace llmfw
