#pragma once
// The request head a client sends to the proxy, and the connection that reads it.

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <boost/asio/steady_timer.hpp>

#include "llmfw/common.hpp"
#include "llmfw/decrypted_relay.hpp"
#include "llmfw/proxy_context.hpp"
#include "llmfw/tls_client.hpp"
#include "llmfw/tls_server.hpp"
#include "llmfw/tls_stream.hpp"

namespace llmfw {

enum class ProxyRequestKind { kConnect, kOther };

struct ProxyRequest {
  ProxyRequestKind kind = ProxyRequestKind::kOther;
  std::string method;          ///< As sent, for example "CONNECT" or "GET".
  std::string target;          ///< The request target as sent, for example "claude.ai:443" or "/proxy.pac".
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

/// One accepted client socket, from its request head to a tunnel or a decrypted relay:
///   - head not complete within listen.idle_timeout, or the client closes first: close
///   - invalid or oversize head: 400, close
///   - GET /proxy.pac: 200 with ctx.pac (the PAC Claude is pointed at), close
///   - any other non-CONNECT request: 405, count non_connect_requests_rejected, close
///   - CONNECT: decideScope() with ctx.certs and ctx.breaker. A target to decrypt for
///     which the client already sent bytes after the head becomes kClientSentEarly.
///     Any tunnel reason: a BlindTunnel with that reason and the bytes after the head.
///   - CONNECT to decrypt:
///       1. Opens a verified TLS connection to the origin (ctx.connector). If the
///          origin's certificate fails verification: a BlindTunnel with
///          kUpstreamVerifyFailed, so the client verifies the origin itself. Any other
///          failure: 502, close.
///       2. Replies 200, then completes TLS with the client using our leaf
///          (ctx.terminator), within upstream.tls_handshake_timeout. If that fails it
///          counts client_tls_handshake_failures and closes both connections; if the
///          client rejected our certificate, it also opens ctx.breaker for the host,
///          so the client's retry is tunneled.
///       3. Hands both TLS connections to a DecryptedRelay.
///     Until step 3 the connection is not in ctx.tunnels; the timeouts bound each step.
/// Every handler runs on the socket's executor, which must be a strand.
class ClientConnection final : public std::enable_shared_from_this<ClientConnection> {
 public:
  ClientConnection(tcp::socket socket, std::uint64_t connection_id, ProxyContext& ctx);

  /// Safe from any thread: the work runs on the socket's executor.
  void start();

 private:
  void readMore();
  void onHead(const ProxyRequest& request);
  void decrypt(const ProxyRequest& request, std::string host);
  void onUpstream(UpstreamResult result, std::unique_ptr<TlsStream> upstream);
  void onClientHandshake(const boost::system::error_code& ec, const ClientTlsResult& result);
  void closeDecryptAttempt();
  void replyAndClose(std::string response);

  tcp::socket socket_;
  std::uint64_t connection_id_;
  ProxyContext& ctx_;
  asio::steady_timer timer_;
  std::vector<std::uint8_t> head_buf_;
  std::size_t filled_ = 0;
  std::string response_;  ///< Kept alive while it is being written.
  DecryptedConnectionInfo info_;  ///< Filled in while setting up decryption.
  std::unique_ptr<TlsStream> upstream_;
  std::unique_ptr<TlsStream> client_tls_;
};

}  // namespace llmfw
