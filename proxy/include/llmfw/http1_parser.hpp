#pragma once
// Incremental HTTP/1.1 framing parser over llhttp. It reads the start line, the
// headers and the message boundaries. It never interprets bodies: body bytes are
// handed on as opaque, de-chunked slices.

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace llmfw {

enum class Http1Mode { kRequest, kResponse };

struct Http1Head {
  // Request fields (kRequest)
  std::string method;
  std::string target;
  // Response fields (kResponse)
  unsigned status = 0;
  std::string reason;
  // Both
  unsigned version_major = 1;
  unsigned version_minor = 1;
  std::vector<std::pair<std::string, std::string>> headers;  ///< Wire order and case.
  bool keep_alive = true;
  bool upgrade = false;  ///< An Upgrade (or CONNECT) request, or a 101 response.
  std::optional<std::uint64_t> content_length;
  bool chunked = false;
};

/// Receives parser events synchronously from inside Http1Parser::feed() and finish().
/// A handler that throws a std::exception turns the feed into kError; the parser stops there.
class Http1Events {
 public:
  virtual ~Http1Events() = default;
  /// Once per message, after the last header. 1xx responses are messages too.
  virtual void onHead(const Http1Head& head) = 0;
  /// De-chunked body bytes. `bytes` is only valid during the call.
  virtual void onBody(std::span<const std::uint8_t> bytes) = 0;
  virtual void onMessageComplete() = 0;
};

enum class FeedStatus {
  kOk,       ///< All input consumed.
  kUpgrade,  ///< The message switched protocols. `consumed` bytes belong to HTTP, and the rest to the new protocol.
  kError,    ///< Framing violation or limit exceeded. The parser accepts no more input; the caller relays raw.
};

struct FeedResult {
  FeedStatus status = FeedStatus::kOk;
  std::size_t consumed = 0;
  std::string error;  ///< llhttp error name and a fixed reason. Never contains message bytes.
};

struct Http1Limits {
  /// Start line plus every header name and value, in bytes, excluding delimiters.
  std::size_t max_head_bytes = 64 * 1024;
  std::size_t max_headers = 256;
};

/// Not thread-safe. There is one instance per direction per connection.
class Http1Parser {
 public:
  Http1Parser(Http1Mode mode, Http1Events& events, Http1Limits limits = {});
  ~Http1Parser();
  Http1Parser(const Http1Parser&) = delete;
  Http1Parser& operator=(const Http1Parser&) = delete;

  /// Feeds wire bytes. Events fire synchronously. The input is never modified.
  /// After kUpgrade or kError, every further call returns the same status with
  /// consumed 0 (until resumeAfterRejectedUpgrade, for an upgrade).
  [[nodiscard]] FeedResult feed(std::span<const std::uint8_t> bytes);

  /// Signals EOF. This completes a body delimited by connection close (onMessageComplete).
  /// kError if EOF falls inside a message whose length is known.
  [[nodiscard]] FeedResult finish();

  /// Response mode only. Call once per request, in request order. The response
  /// answering a HEAD request has no body, whatever its headers say. Responses
  /// beyond the requests noted here are taken to answer non-HEAD requests.
  void expectResponse(bool to_head_request);

  /// Request mode only, after feed returned kUpgrade: the server did not switch
  /// protocols, so the connection stays HTTP and parsing continues with the next
  /// request. Does nothing in any other state.
  void resumeAfterRejectedUpgrade();

 private:
  struct Impl;  // Holds llhttp_t and llhttp_settings_t, so llhttp.h stays out of this header.
  std::unique_ptr<Impl> impl_;
};

}  // namespace llmfw
