#pragma once
// Client-side TLS termination for decrypted (scoped) connections.

#include <chrono>
#include <functional>
#include <string>
#include <vector>

#include <boost/asio/ssl/context.hpp>
#include <boost/system/error_code.hpp>

#include "llmfw/cert_store.hpp"
#include "llmfw/common.hpp"
#include "llmfw/tls_stream.hpp"

namespace llmfw {

struct ClientTlsResult {
  std::string sni;   ///< Normalized SNI the client sent, or empty if it sent none.
  std::string alpn;  ///< Selected protocol, or empty if none was negotiated (HTTP/1.1 is then implied).
  /// The client aborted after receiving our certificate: a certificate-related alert
  /// (bad_certificate, unknown_ca, certificate_unknown, ...) or EOF mid-handshake.
  /// This is the signal for ClientTlsBreaker::recordFailure.
  bool client_rejected_cert = false;
  Clock::duration handshake_time{};
};

/// Called exactly once, on the stream's executor. A non-zero error means the handshake failed.
using ClientHandshakeHandler = std::function<void(const boost::system::error_code&, ClientTlsResult)>;

/// Owns the server-side TLS context: TLS 1.2 or later, the store's leaf certificate,
/// and ALPN selection from `client_alpn` only (server preference order). If the client
/// offers ALPN but none of those, the handshake continues without ALPN, which means HTTP/1.1.
class ClientTlsTerminator {
 public:
  /// @param client_alpn protocols we may select, such as {"http/1.1"}. There is no h2
  ///        until an HttpSession for HTTP/2 exists.
  /// @throws std::invalid_argument for an invalid ALPN name.
  /// @throws std::runtime_error on an OpenSSL failure.
  ClientTlsTerminator(const LeafCertStore& certs, std::vector<std::string> client_alpn);

  /// The context a TlsStream for an accepted client socket must be constructed with.
  [[nodiscard]] asio::ssl::context& context() { return ctx_; }

  /// Runs the server handshake. Before anything is sent, the ClientHello must carry an
  /// SNI that normalizes to `expected_host` (the CONNECT host), so a client cannot get
  /// our certificate for a host it did not CONNECT to; otherwise the handshake fails
  /// with an unrecognized_name alert. If the handshake has not finished after `timeout`,
  /// the socket is closed and the handler gets asio::error::timed_out (never counted as
  /// client_rejected_cert). The stream must outlive the handshake.
  void asyncHandshake(TlsStream& stream, std::string expected_host, std::chrono::milliseconds timeout,
                      ClientHandshakeHandler handler);

 private:
  std::vector<unsigned char> alpn_wire_;
  asio::ssl::context ctx_;
};

}  // namespace llmfw
