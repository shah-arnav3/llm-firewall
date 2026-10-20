#pragma once
// Upstream TLS origination with strict verification.

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/ssl/context.hpp>
#include <boost/asio/thread_pool.hpp>

#include "llmfw/config.hpp"
#include "llmfw/tls_stream.hpp"
#include "llmfw/trust_verifier.hpp"

namespace llmfw {

struct UpstreamResult {
  enum class Status {
    kOk,
    kResolveFailed,
    kConnectFailed,
    kHandshakeFailed,  ///< TLS protocol failure other than verification.
    kVerifyFailed,     ///< Chain or host name rejected by the UpstreamTrustVerifier.
    kTimeout,
  };
  Status status = Status::kConnectFailed;
  std::string alpn;  ///< Protocol the origin selected, or empty if it selected none.
  std::chrono::microseconds connect_time{0};  ///< From asyncConnect to completion.
  std::string detail;  ///< Why it failed, for operational logs only.
};

using UpstreamHandler = std::function<void(UpstreamResult, std::unique_ptr<TlsStream>)>;

/// Opens a NEW TLS connection to the origin for each decrypted client connection.
/// It sets SNI to the CONNECT host, offers only the configured ALPN protocols (so
/// both sides speak the same protocol), and requires TLS 1.2 or later. Connections
/// are never pooled or shared between client connections.
///
/// OpenSSL does not judge the server's certificates. After the handshake, the chain is
/// handed to the UpstreamTrustVerifier on a private thread pool (verification can block
/// on the network), and the stream is handed out only if it passes. Nothing is written
/// to the origin before then.
///
/// The connector must outlive every operation it started: destroy it only after the
/// I/O context has stopped.
class UpstreamTlsConnector {
 public:
  /// @param alpn protocol names to offer, such as "http/1.1". Each is 1-255 bytes.
  /// @throws std::invalid_argument for an invalid ALPN name.
  /// @throws std::runtime_error on an OpenSSL failure.
  UpstreamTlsConnector(const UpstreamConfig& cfg, std::shared_ptr<const UpstreamTrustVerifier> verifier,
                       std::vector<std::string> alpn);
  ~UpstreamTlsConnector();
  UpstreamTlsConnector(const UpstreamTlsConnector&) = delete;
  UpstreamTlsConnector& operator=(const UpstreamTlsConnector&) = delete;

  /// Resolves and connects within connect_timeout, then handshakes and verifies within
  /// tls_handshake_timeout. Calls `handler` exactly once, on `ex`: with kOk and the
  /// connected stream, or with another status and nullptr.
  /// @param endpoint_override tests only: connect here instead of resolving `host`
  ///        (SNI and verification still use `host`). Must outlive the operation.
  void asyncConnect(asio::any_io_executor ex, std::string host, std::uint16_t port, UpstreamHandler handler,
                    const tcp::endpoint* endpoint_override = nullptr);

 private:
  struct Operation;

  UpstreamConfig cfg_;
  std::shared_ptr<const UpstreamTrustVerifier> verifier_;
  asio::ssl::context ctx_;
  asio::thread_pool verify_pool_;
};

}  // namespace llmfw
