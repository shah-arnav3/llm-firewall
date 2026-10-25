#include "llmfw/websocket.hpp"

#include <algorithm>
#include <utility>

namespace llmfw {

namespace {

constexpr std::uint8_t kFin = 0x80;
constexpr std::uint8_t kRsv1 = 0x40;
constexpr std::uint8_t kRsv2And3 = 0x30;
constexpr std::uint8_t kOpcodeBits = 0x0F;
constexpr std::uint8_t kMaskBit = 0x80;
constexpr std::uint8_t kLengthBits = 0x7F;
constexpr std::uint8_t kLength16 = 126;
constexpr std::uint8_t kLength64 = 127;
constexpr std::uint64_t kMaxControlPayload = 125;

bool isControl(std::uint8_t opcode) { return (opcode & 0x8) != 0; }

}  // namespace

WebSocketFrameDecoder::WebSocketFrameDecoder(WsSender sender, std::size_t message_cap)
    : sender_(sender), message_cap_(message_cap) {}

WsDecodeResult WebSocketFrameDecoder::feed(std::span<const std::uint8_t> wire,
                                           const std::function<void(WsMessage&&)>& on_message) {
  if (!error_.empty()) {
    return {WsDecodeStatus::kError, error_};
  }
  while (!wire.empty()) {
    if (!in_payload_) {
      while (!wire.empty() && header_.size() < headerLength()) {
        header_.push_back(wire.front());
        wire = wire.subspan(1);
      }
      if (header_.size() < headerLength()) {
        break;
      }
      if (std::string error = startFrame(); !error.empty()) {
        return fail(std::move(error));
      }
    } else {
      const auto n = static_cast<std::size_t>(std::min<std::uint64_t>(frame_remaining_, wire.size()));
      appendPayload(wire.first(n));
      wire = wire.subspan(n);
      frame_remaining_ -= n;
    }
    if (frame_remaining_ == 0) {
      endFrame(on_message);
    }
  }
  return {};
}

std::size_t WebSocketFrameDecoder::headerLength() const {
  if (header_.size() < 2) {
    return 2;
  }
  const std::uint8_t length = header_[1] & kLengthBits;
  const std::size_t extended = length == kLength16 ? 2 : length == kLength64 ? 8 : 0;
  const std::size_t mask = (header_[1] & kMaskBit) != 0 ? 4 : 0;
  return 2 + extended + mask;
}

std::string WebSocketFrameDecoder::startFrame() {
  const std::uint8_t first = header_[0];
  const std::uint8_t opcode = first & kOpcodeBits;
  const bool fin = (first & kFin) != 0;
  const bool rsv1 = (first & kRsv1) != 0;
  frame_masked_ = (header_[1] & kMaskBit) != 0;

  std::uint64_t length = header_[1] & kLengthBits;
  std::size_t pos = 2;
  if (length == kLength16 || length == kLength64) {
    const std::size_t bytes = length == kLength16 ? 2 : 8;
    length = 0;
    for (std::size_t i = 0; i < bytes; ++i) {
      length = (length << 8) | header_[pos++];
    }
    if (bytes == 8 && (length >> 63) != 0) {
      return "64-bit payload length has its top bit set";
    }
  }
  if (frame_masked_) {
    std::copy_n(header_.begin() + static_cast<std::ptrdiff_t>(pos), 4, mask_key_.begin());
  }

  if (closed_) {
    return "frame after a close frame";
  }
  if (frame_masked_ != (sender_ == WsSender::kClient)) {
    return sender_ == WsSender::kClient ? "client frame is not masked" : "server frame is masked";
  }
  if ((first & kRsv2And3) != 0) {
    return "RSV2 or RSV3 is set";
  }
  if (isControl(opcode)) {
    if (opcode != ws_opcode::kClose && opcode != ws_opcode::kPing && opcode != ws_opcode::kPong) {
      return "reserved control opcode";
    }
    if (!fin || length > kMaxControlPayload) {
      return "control frame is fragmented or longer than 125 bytes";
    }
    if (rsv1) {
      return "RSV1 is set on a control frame";
    }
    control_ = WsMessage{.opcode = opcode};
  } else if (opcode == ws_opcode::kContinuation) {
    if (!in_data_message_) {
      return "continuation frame with no message to continue";
    }
    if (rsv1) {
      return "RSV1 is set on a continuation frame";
    }
  } else if (opcode == ws_opcode::kText || opcode == ws_opcode::kBinary) {
    if (in_data_message_) {
      return "new data message before the previous one ended";
    }
    data_ = WsMessage{.opcode = opcode, .compressed = rsv1};
    in_data_message_ = true;
  } else {
    return "reserved data opcode";
  }

  frame_opcode_ = opcode;
  frame_fin_ = fin;
  frame_remaining_ = length;
  mask_offset_ = 0;
  in_payload_ = true;
  header_.clear();
  return {};
}

void WebSocketFrameDecoder::appendPayload(std::span<const std::uint8_t> bytes) {
  WsMessage& message = isControl(frame_opcode_) ? control_ : data_;
  message.total_bytes += bytes.size();
  const std::size_t room = message_cap_ > message.payload.size() ? message_cap_ - message.payload.size() : 0;
  const std::size_t kept = std::min(room, bytes.size());
  const std::size_t start = message.payload.size();
  message.payload.insert(message.payload.end(), bytes.begin(), bytes.begin() + static_cast<std::ptrdiff_t>(kept));
  if (frame_masked_) {
    for (std::size_t i = 0; i < kept; ++i) {
      message.payload[start + i] ^= mask_key_[(mask_offset_ + i) % 4];
    }
  }
  mask_offset_ += bytes.size();
  message.truncated = message.total_bytes > message.payload.size();
}

void WebSocketFrameDecoder::endFrame(const std::function<void(WsMessage&&)>& on_message) {
  in_payload_ = false;
  if (isControl(frame_opcode_)) {
    closed_ = frame_opcode_ == ws_opcode::kClose;
    on_message(std::move(control_));
    control_ = WsMessage{};
  } else if (frame_fin_) {
    in_data_message_ = false;
    on_message(std::move(data_));
    data_ = WsMessage{};
  }
}

WsDecodeResult WebSocketFrameDecoder::fail(std::string error) {
  error_ = std::move(error);
  return {WsDecodeStatus::kError, error_};
}

}  // namespace llmfw
