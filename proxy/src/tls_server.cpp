#include "llmfw/tls_server.hpp"

#include <memory>
#include <optional>
#include <string_view>

#include <boost/asio/ssl/error.hpp>
#include <boost/asio/steady_timer.hpp>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include "llmfw/alpn.hpp"
#include "llmfw/host_scope.hpp"
#include "llmfw/openssl_ptr.hpp"

namespace llmfw {

namespace {

/// Per-handshake state, reachable from OpenSSL callbacks through the SSL's ex_data.
struct HandshakeState {
  std::string expected_host;
  std::string sni;
  bool hello_seen = false;  ///< True once the ClientHello passed our checks.
  bool timed_out = false;
};

int handshakeStateIndex() {
  static const int index = SSL_get_ex_new_index(0, nullptr, nullptr, nullptr, nullptr);
  return index;
}

/// The host name from a server_name extension body (RFC 6066), or nullopt if malformed.
std::optional<std::string_view> parseServerName(const unsigned char* data, std::size_t length) {
  if (length < 2) {
    return std::nullopt;
  }
  const std::size_t list_length = (std::size_t{data[0]} << 8) | data[1];
  if (list_length != length - 2 || list_length < 3) {
    return std::nullopt;
  }
  const unsigned char* entry = data + 2;
  const std::size_t name_length = (std::size_t{entry[1]} << 8) | entry[2];
  if (entry[0] != TLSEXT_NAMETYPE_host_name || 3 + name_length > list_length) {
    return std::nullopt;
  }
  return std::string_view(reinterpret_cast<const char*>(entry + 3), name_length);
}

/// Runs before OpenSSL processes the ClientHello, even when it has no SNI.
int onClientHello(SSL* ssl, int* alert, void* /*arg*/) {
  auto* state = static_cast<HandshakeState*>(SSL_get_ex_data(ssl, handshakeStateIndex()));
  const unsigned char* ext = nullptr;
  std::size_t ext_length = 0;
  std::optional<std::string_view> raw;
  if (state != nullptr && SSL_client_hello_get0_ext(ssl, TLSEXT_TYPE_server_name, &ext, &ext_length) == 1) {
    raw = parseServerName(ext, ext_length);
  }
  const std::optional<std::string> sni = raw ? HostScope::normalizeHost(*raw) : std::nullopt;
  if (state == nullptr || !sni || *sni != state->expected_host) {
    if (state != nullptr && sni) {
      state->sni = *sni;
    }
    *alert = SSL_AD_UNRECOGNIZED_NAME;
    return SSL_CLIENT_HELLO_ERROR;
  }
  state->sni = *sni;
  state->hello_seen = true;
  return SSL_CLIENT_HELLO_SUCCESS;
}

int onAlpn(SSL* /*ssl*/, const unsigned char** out, unsigned char* out_length, const unsigned char* in,
           unsigned int in_length, void* arg) {
  const auto* ours = static_cast<const std::vector<unsigned char>*>(arg);
  unsigned char* selected = nullptr;
  if (SSL_select_next_proto(&selected, out_length, ours->data(), static_cast<unsigned int>(ours->size()), in,
                            in_length) != OPENSSL_NPN_NEGOTIATED) {
    return SSL_TLSEXT_ERR_NOACK;
  }
  *out = selected;
  return SSL_TLSEXT_ERR_OK;
}

/// True for the alerts a client sends when it does not accept our certificate.
bool isCertificateAlert(const boost::system::error_code& ec) {
  if (ec.category() != asio::error::get_ssl_category()) {
    return false;
  }
  switch (ERR_GET_REASON(static_cast<unsigned long>(ec.value()))) {
    case SSL_R_SSLV3_ALERT_BAD_CERTIFICATE:
    case SSL_R_SSLV3_ALERT_CERTIFICATE_UNKNOWN:
    case SSL_R_SSLV3_ALERT_UNSUPPORTED_CERTIFICATE:
    case SSL_R_SSLV3_ALERT_CERTIFICATE_REVOKED:
    case SSL_R_SSLV3_ALERT_CERTIFICATE_EXPIRED:
    case SSL_R_TLSV1_ALERT_UNKNOWN_CA:
    case SSL_R_TLSV1_ALERT_ACCESS_DENIED:
      return true;
    default:
      return false;
  }
}

bool isEof(const boost::system::error_code& ec) {
  return ec == asio::error::eof || ec == asio::ssl::error::stream_truncated || ec == asio::error::connection_reset;
}

}  // namespace

ClientTlsTerminator::ClientTlsTerminator(const LeafCertStore& certs, std::vector<std::string> client_alpn)
    : alpn_wire_(alpnWireFormat(client_alpn)), ctx_(asio::ssl::context::tls_server) {
  SSL_CTX* ctx = ctx_.native_handle();
  if (SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION) != 1 ||
      SSL_CTX_use_certificate(ctx, &certs.certificate()) != 1 ||
      SSL_CTX_use_PrivateKey(ctx, &certs.privateKey()) != 1 || SSL_CTX_check_private_key(ctx) != 1) {
    throwOpenSslError("set up client TLS");
  }
  SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION | SSL_OP_NO_RENEGOTIATION);
  SSL_CTX_set_client_hello_cb(ctx, &onClientHello, nullptr);
  if (!alpn_wire_.empty()) {
    SSL_CTX_set_alpn_select_cb(ctx, &onAlpn, &alpn_wire_);
  }
}

void ClientTlsTerminator::asyncHandshake(TlsStream& stream, std::string expected_host,
                                         std::chrono::milliseconds timeout, ClientHandshakeHandler handler) {
  // The state outlives the handshake: the completion handler owns it, and it is
  // detached from the SSL before the handler runs.
  auto state = std::make_shared<HandshakeState>();
  state->expected_host = std::move(expected_host);
  SSL_set_ex_data(stream.native_handle(), handshakeStateIndex(), state.get());

  auto timer = std::make_shared<asio::steady_timer>(stream.get_executor());
  timer->expires_after(timeout);
  timer->async_wait([&stream, state](const boost::system::error_code& ec) {
    if (!ec) {
      state->timed_out = true;
      boost::system::error_code ignored;
      stream.lowest_layer().close(ignored);
    }
  });

  const Clock::time_point started = Clock::now();
  stream.async_handshake(
      asio::ssl::stream_base::server,
      [&stream, state, timer, started, handler = std::move(handler)](const boost::system::error_code& ec) {
        timer->cancel();
        SSL_set_ex_data(stream.native_handle(), handshakeStateIndex(), nullptr);
        ClientTlsResult result;
        result.sni = state->sni;
        result.handshake_time = Clock::now() - started;
        if (state->timed_out) {
          // A stalled client is not a rejection of our certificate.
          handler(asio::error::timed_out, std::move(result));
          return;
        }
        if (!ec) {
          const unsigned char* alpn = nullptr;
          unsigned int alpn_length = 0;
          SSL_get0_alpn_selected(stream.native_handle(), &alpn, &alpn_length);
          result.alpn.assign(reinterpret_cast<const char*>(alpn), alpn_length);
        } else {
          // Only after a valid ClientHello has the client seen our certificate.
          result.client_rejected_cert = state->hello_seen && (isCertificateAlert(ec) || isEof(ec));
        }
        handler(ec, std::move(result));
      });
}

}  // namespace llmfw
