#pragma once
// The request head a client sends to the proxy before a tunnel is opened.

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>

namespace llmfw {

enum class ProxyRequestKind { kConnect, kOther };

struct ProxyRequest {
  ProxyRequestKind kind = ProxyRequestKind::kOther;
  std::string host;            ///< CONNECT only: the authority host, without brackets for IPv6.
  std::uint16_t port = 0;      ///< CONNECT only.
  std::string user_agent;      ///< First User-Agent header, trimmed. Empty if absent.
  std::size_t head_bytes = 0;  ///< Bytes up to and including the blank line.
};

enum class ProxyRequestParse { kNeedMore, kComplete, kInvalid };

/// Largest request head accepted, including the terminating blank line.
inline constexpr std::size_t kMaxProxyRequestHeadBytes = 16 * 1024;

/// Parses the request head at the start of `buffer`. Pure and safe on any input.
///   - kNeedMore: no blank line yet and the buffer is under kMaxProxyRequestHeadBytes.
///   - kInvalid:  the head is malformed or longer than kMaxProxyRequestHeadBytes.
///   - kComplete: `out` is filled. Bytes after out.head_bytes belong to the tunnel.
/// Accepted form: "METHOD SP target SP HTTP/1.0|HTTP/1.1" CRLF, header lines CRLF, CRLF.
/// A CONNECT target must be "host:port" or "[ipv6]:port" with a port of 1-65535. Any
/// other well-formed method gives kOther with an empty host. A header line without a
/// colon, or one starting with whitespace (obsolete line folding), is invalid.
/// `out` is reset on every call and is meaningful only for kComplete.
[[nodiscard]] ProxyRequestParse parseProxyRequest(std::span<const std::uint8_t> buffer, ProxyRequest& out);

}  // namespace llmfw
