#pragma once
// Incremental RFC 6455 frame decoding for one direction of a WebSocket connection.

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <span>
#include <string>
#include <vector>

namespace llmfw {

/// Which side sent the frames: a client masks every frame, a server never does.
enum class WsSender { kClient, kServer };

/// WebSocket opcodes (RFC 6455 section 5.2).
namespace ws_opcode {
constexpr std::uint8_t kContinuation = 0x0;
constexpr std::uint8_t kText = 0x1;
constexpr std::uint8_t kBinary = 0x2;
constexpr std::uint8_t kClose = 0x8;
constexpr std::uint8_t kPing = 0x9;
constexpr std::uint8_t kPong = 0xA;
}  // namespace ws_opcode

/// One complete message: a data message with its fragments joined, or one control frame.
struct WsMessage {
  std::uint8_t opcode = 0;  ///< kText, kBinary, kClose, kPing or kPong.
  std::vector<std::uint8_t> payload;  ///< Unmasked, at most the decoder's message cap.
  std::uint64_t total_bytes = 0;      ///< The whole payload's size, including bytes past the cap.
  bool truncated = false;             ///< total_bytes > payload.size().
  bool compressed = false;            ///< RSV1 was set on the first frame (permessage-deflate).
};

enum class WsDecodeStatus { kOk, kError };

struct WsDecodeResult {
  WsDecodeStatus status = WsDecodeStatus::kOk;
  std::string error;  ///< Why the stream is not valid WebSocket; set only with kError.
};

/// Decodes the frames one side sends, from bytes fed in any chunking. It does no I/O
/// and never changes its input: unmasking happens on the copy it keeps.
///
/// Calls on_message, from inside feed(), for each message as its last frame ends.
/// A control frame sent between the fragments of a data message is its own message,
/// delivered before the data message. Each payload keeps at most `message_cap` bytes.
///
/// These are protocol errors (kError), after which every feed returns the same error:
///   - a frame from the wrong sender's masking (kClient frames unmasked, kServer masked);
///   - RSV2 or RSV3 set, or RSV1 set anywhere but the first frame of a data message;
///   - a reserved opcode;
///   - a control frame that is fragmented or longer than 125 bytes;
///   - a continuation with no message to continue, or a new data message before the
///     previous one has ended;
///   - a 64-bit length with its top bit set;
///   - any frame after a close frame.
class WebSocketFrameDecoder {
 public:
  WebSocketFrameDecoder(WsSender sender, std::size_t message_cap);

  [[nodiscard]] WsDecodeResult feed(std::span<const std::uint8_t> wire,
                                    const std::function<void(WsMessage&&)>& on_message);

 private:
  [[nodiscard]] std::size_t headerLength() const;
  /// Validates the complete header in header_ and sets up the frame; returns an error or "".
  [[nodiscard]] std::string startFrame();
  void appendPayload(std::span<const std::uint8_t> bytes);
  void endFrame(const std::function<void(WsMessage&&)>& on_message);
  WsDecodeResult fail(std::string error);

  WsSender sender_;
  std::size_t message_cap_;
  std::vector<std::uint8_t> header_;  ///< The current frame's header while it is incomplete.
  bool in_payload_ = false;
  std::uint64_t frame_remaining_ = 0;
  std::uint8_t frame_opcode_ = 0;
  bool frame_fin_ = false;
  bool frame_masked_ = false;
  std::array<std::uint8_t, 4> mask_key_{};
  std::uint64_t mask_offset_ = 0;
  WsMessage data_;     ///< The data message being assembled.
  bool in_data_message_ = false;
  WsMessage control_;  ///< The control frame being read.
  bool closed_ = false;  ///< A close frame has ended.
  std::string error_;
};

}  // namespace llmfw
