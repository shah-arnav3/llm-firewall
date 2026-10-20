#include "llmfw/tls_client.hpp"

#include <utility>

#include <boost/asio/connect.hpp>
#include <boost/asio/executor_work_guard.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/steady_timer.hpp>

#include <openssl/ssl.h>

#include "llmfw/alpn.hpp"
#include "llmfw/openssl_ptr.hpp"

namespace llmfw {

namespace {

// Verifications in flight at once. Each one usually takes milliseconds; more threads
// only help when many evaluations wait on the network together.
constexpr std::size_t kVerifyThreads = 2;

}  // namespace

/// One connection attempt. Every member is used only on `executor`, except the chain
/// copy handed to the verify pool, which nothing else touches.
struct UpstreamTlsConnector::Operation : std::enable_shared_from_this<Operation> {
  Operation(UpstreamTlsConnector& connector, asio::any_io_executor ex, std::string host, std::uint16_t port,
            UpstreamHandler handler)
      : connector(connector),
        executor(ex),
        resolver(ex),
        timer(ex),
        stream(std::make_unique<TlsStream>(ex, connector.ctx_)),
        host(std::move(host)),
        port(port),
        handler(std::move(handler)),
        started(Clock::now()) {}

  void start() {
    if (SSL_set_tlsext_host_name(stream->native_handle(), host.c_str()) != 1) {
      complete(UpstreamResult::Status::kHandshakeFailed, "cannot set SNI");
      return;
    }
    arm(connector.cfg_.connect_timeout);
    resolver.async_resolve(host, std::to_string(port),
                           [self = shared_from_this()](const boost::system::error_code& ec,
                                                       const tcp::resolver::results_type& results) {
                             self->onResolved(ec, results);
                           });
  }

  void arm(std::chrono::milliseconds after) {
    timer.expires_after(after);
    timer.async_wait([self = shared_from_this()](const boost::system::error_code& ec) {
      if (ec || self->done) {
        return;
      }
      // The pending resolve, connect, handshake or verification then completes as a timeout.
      self->timed_out = true;
      self->resolver.cancel();
      boost::system::error_code ignored;
      self->stream->lowest_layer().close(ignored);
    });
  }

  void onResolved(const boost::system::error_code& ec, const tcp::resolver::results_type& results) {
    if (ec) {
      fail(UpstreamResult::Status::kResolveFailed, "resolve: " + ec.message());
      return;
    }
    asio::async_connect(stream->lowest_layer(), results,
                        [self = shared_from_this()](const boost::system::error_code& connect_ec, const tcp::endpoint&) {
                          self->onConnected(connect_ec);
                        });
  }

  void onConnected(const boost::system::error_code& ec) {
    if (ec) {
      fail(UpstreamResult::Status::kConnectFailed, "connect: " + ec.message());
      return;
    }
    boost::system::error_code ignored;
    stream->lowest_layer().set_option(tcp::no_delay(true), ignored);
    arm(connector.cfg_.tls_handshake_timeout);
    stream->async_handshake(asio::ssl::stream_base::client,
                            [self = shared_from_this()](const boost::system::error_code& handshake_ec) {
                              self->onHandshake(handshake_ec);
                            });
  }

  void onHandshake(const boost::system::error_code& ec) {
    if (ec) {
      fail(UpstreamResult::Status::kHandshakeFailed, "handshake: " + ec.message());
      return;
    }
    // On the client side the peer chain includes the leaf. The copy holds its own
    // references, so the verify thread never touches this connection's SSL object.
    STACK_OF(X509)* chain = X509_chain_up_ref(SSL_get_peer_cert_chain(stream->native_handle()));
    // The work guard keeps the executor's context running until the result is posted
    // back, even when nothing else is pending on it.
    asio::post(connector.verify_pool_,
               [self = shared_from_this(), chain, work = asio::make_work_guard(executor)] {
                 VerifyResult result = self->connector.verifier_->verify(chain, self->host);
                 sk_X509_pop_free(chain, X509_free);
                 asio::post(self->executor, [self, result = std::move(result)] { self->onVerified(result); });
               });
  }

  void onVerified(const VerifyResult& result) {
    if (done) {
      return;
    }
    if (timed_out) {
      complete(UpstreamResult::Status::kTimeout, "timed out verifying the certificate");
      return;
    }
    if (!result.ok) {
      complete(UpstreamResult::Status::kVerifyFailed, result.reason);
      return;
    }
    const unsigned char* alpn = nullptr;
    unsigned int alpn_length = 0;
    SSL_get0_alpn_selected(stream->native_handle(), &alpn, &alpn_length);
    selected_alpn.assign(reinterpret_cast<const char*>(alpn), alpn_length);
    complete(UpstreamResult::Status::kOk, {});
  }

  /// A failure reported by an I/O step, which is a timeout if the timer fired first.
  void fail(UpstreamResult::Status status, std::string detail) {
    if (timed_out) {
      complete(UpstreamResult::Status::kTimeout, "timed out");
    } else {
      complete(status, std::move(detail));
    }
  }

  void complete(UpstreamResult::Status status, std::string detail) {
    if (done) {
      return;
    }
    done = true;
    timer.cancel();
    UpstreamResult result;
    result.status = status;
    result.detail = std::move(detail);
    result.alpn = std::move(selected_alpn);
    result.connect_time = std::chrono::duration_cast<std::chrono::microseconds>(Clock::now() - started);
    if (status != UpstreamResult::Status::kOk) {
      boost::system::error_code ignored;
      stream->lowest_layer().close(ignored);
      stream.reset();
    }
    UpstreamHandler callback = std::move(handler);
    callback(std::move(result), std::move(stream));
  }

  UpstreamTlsConnector& connector;
  asio::any_io_executor executor;
  tcp::resolver resolver;
  asio::steady_timer timer;
  std::unique_ptr<TlsStream> stream;
  std::string host;
  std::uint16_t port;
  UpstreamHandler handler;
  Clock::time_point started;
  std::string selected_alpn;
  bool done = false;
  bool timed_out = false;
};

UpstreamTlsConnector::UpstreamTlsConnector(const UpstreamConfig& cfg,
                                           std::shared_ptr<const UpstreamTrustVerifier> verifier,
                                           std::vector<std::string> alpn)
    : cfg_(cfg), verifier_(std::move(verifier)), ctx_(asio::ssl::context::tls_client), verify_pool_(kVerifyThreads) {
  SSL_CTX* ctx = ctx_.native_handle();
  if (SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION) != 1) {
    throwOpenSslError("set the minimum upstream TLS version");
  }
  SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION);
  // The trust verifier judges the chain after the handshake; see the class comment.
  SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
  const std::vector<unsigned char> wire = alpnWireFormat(alpn);
  // SSL_CTX_set_alpn_protos returns 0 on success.
  if (!wire.empty() && SSL_CTX_set_alpn_protos(ctx, wire.data(), static_cast<unsigned int>(wire.size())) != 0) {
    throwOpenSslError("set the upstream ALPN protocols");
  }
}

UpstreamTlsConnector::~UpstreamTlsConnector() { verify_pool_.join(); }

void UpstreamTlsConnector::asyncConnect(asio::any_io_executor ex, std::string host, std::uint16_t port,
                                        UpstreamHandler handler) {
  auto operation = std::make_shared<Operation>(*this, ex, std::move(host), port, std::move(handler));
  asio::post(ex, [operation] { operation->start(); });
}

}  // namespace llmfw
