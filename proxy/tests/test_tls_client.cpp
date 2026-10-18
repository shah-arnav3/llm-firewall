#include <gtest/gtest.h>

#include <atomic>
#include <filesystem>
#include <fstream>
#include <memory>
#include <optional>
#include <string>
#include <thread>

#include <boost/asio/io_context.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/ssl/context.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/write.hpp>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include <unistd.h>

#include "llmfw/openssl_ptr.hpp"
#include "llmfw/setup_x509.hpp"
#include "llmfw/tls_client.hpp"
#include "net_test_util.hpp"

namespace llmfw {
namespace {

namespace fs = std::filesystem;
using test::Upstream;
using std::chrono::milliseconds;

/// A fresh temp directory, removed with everything in it when the object goes away.
class TempDir {
 public:
  TempDir() {
    std::string tmpl = (fs::temp_directory_path() / "llmfw-tlsc-XXXXXX").string();
    path_ = ::mkdtemp(tmpl.data());
  }
  ~TempDir() { fs::remove_all(path_); }
  TempDir(const TempDir&) = delete;
  TempDir& operator=(const TempDir&) = delete;
  [[nodiscard]] const fs::path& path() const { return path_; }

 private:
  fs::path path_;
};

/// A test CA (no name constraints, so it can vouch for "localhost") and a leaf it signed.
struct TestPki {
  EvpPkeyPtr ca_key{EVP_EC_gen("P-256")};
  X509Ptr ca{X509_new()};
  EvpPkeyPtr leaf_key{EVP_EC_gen("P-256")};
  X509Ptr leaf{X509_new()};

  explicit TestPki(const std::string& leaf_san = "DNS:localhost") {
    X509_set_version(ca.get(), X509_VERSION_3);
    setup::setRandomSerial(*ca);
    setup::setValidity(*ca, std::chrono::days{2});
    X509_NAME_add_entry_by_txt(X509_get_subject_name(ca.get()), "CN", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char*>("tls client test CA"), -1, -1, 0);
    X509_set_issuer_name(ca.get(), X509_get_subject_name(ca.get()));
    X509_set_pubkey(ca.get(), ca_key.get());
    setup::addExtension(*ca, *ca, NID_basic_constraints, "critical,CA:TRUE");
    setup::addExtension(*ca, *ca, NID_key_usage, "critical,keyCertSign");
    setup::addExtension(*ca, *ca, NID_subject_key_identifier, "hash");
    X509_sign(ca.get(), ca_key.get(), EVP_sha256());

    // macOS rejects a leaf without a subject, key usage or basic constraints as "not standards compliant".
    X509_set_version(leaf.get(), X509_VERSION_3);
    setup::setRandomSerial(*leaf);
    setup::setValidity(*leaf, std::chrono::days{1});
    X509_NAME_add_entry_by_txt(X509_get_subject_name(leaf.get()), "CN", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char*>("tls client test leaf"), -1, -1, 0);
    X509_set_issuer_name(leaf.get(), X509_get_subject_name(ca.get()));
    X509_set_pubkey(leaf.get(), leaf_key.get());
    setup::addExtension(*leaf, *ca, NID_basic_constraints, "critical,CA:FALSE");
    setup::addExtension(*leaf, *ca, NID_key_usage, "critical,digitalSignature");
    setup::addExtension(*leaf, *ca, NID_ext_key_usage, "serverAuth");
    setup::addExtension(*leaf, *ca, NID_authority_key_identifier, "keyid:always");
    setup::addExtension(*leaf, *ca, NID_subject_alt_name, leaf_san);
    X509_sign(leaf.get(), ca_key.get(), EVP_sha256());
  }

  /// Writes the CA certificate as a PEM bundle and returns its path.
  [[nodiscard]] fs::path writeBundle(const TempDir& tmp) const {
    const fs::path path = tmp.path() / "bundle.pem";
    const BioPtr bio(BIO_new_file(path.c_str(), "w"));
    PEM_write_bio_X509(bio.get(), ca.get());
    return path;
  }
};

/// What the test TLS server saw from the client.
struct ServerSeen {
  std::string sni;
  std::string alpn_offered;  ///< The client's ALPN list in wire format.
  std::string received;      ///< Application data read after the handshake.
};

/// Serves one TLS connection on a thread: handshakes with `pki`'s leaf (and `server_alpn`
/// selected if the client offers it), then echoes once.
class TlsServer {
 public:
  explicit TlsServer(const TestPki& pki, std::string server_alpn = "http/1.1", int max_version = 0)
      : ctx_(asio::ssl::context::tls_server),
        server_alpn_(std::move(server_alpn)),
        upstream_([this](tcp::socket& socket) { serve(socket); }) {
    SSL_CTX* ctx = ctx_.native_handle();
    SSL_CTX_use_certificate(ctx, pki.leaf.get());
    SSL_CTX_use_PrivateKey(ctx, pki.leaf_key.get());
    if (max_version != 0) {
      SSL_CTX_set_security_level(ctx, 0);
      SSL_CTX_set_min_proto_version(ctx, 0);
      SSL_CTX_set_max_proto_version(ctx, max_version);
    }
    SSL_CTX_set_tlsext_servername_callback(ctx, &TlsServer::onServerName);
    SSL_CTX_set_tlsext_servername_arg(ctx, this);
    SSL_CTX_set_alpn_select_cb(ctx, &TlsServer::onAlpn, this);
  }

  [[nodiscard]] std::uint16_t port() const { return upstream_.port(); }
  /// Waits for the connection to finish, then returns what was seen.
  [[nodiscard]] ServerSeen seen() {
    while (!finished_.load()) {
      std::this_thread::sleep_for(milliseconds{5});
    }
    return seen_;
  }

 private:
  static int onServerName(SSL* ssl, int*, void* arg) {
    const char* name = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    static_cast<TlsServer*>(arg)->seen_.sni = name == nullptr ? "" : name;
    return SSL_TLSEXT_ERR_OK;
  }

  static int onAlpn(SSL*, const unsigned char** out, unsigned char* outlen, const unsigned char* in,
                    unsigned int inlen, void* arg) {
    auto* self = static_cast<TlsServer*>(arg);
    self->seen_.alpn_offered.assign(reinterpret_cast<const char*>(in), inlen);
    if (self->server_alpn_.empty() ||
        self->seen_.alpn_offered.find(self->server_alpn_) == std::string::npos) {
      return SSL_TLSEXT_ERR_NOACK;
    }
    *out = reinterpret_cast<const unsigned char*>(in + self->seen_.alpn_offered.find(self->server_alpn_));
    *outlen = static_cast<unsigned char>(self->server_alpn_.size());
    return SSL_TLSEXT_ERR_OK;
  }

  void serve(tcp::socket& socket) {
    asio::ssl::stream<tcp::socket&> tls(socket, ctx_);
    boost::system::error_code ec;
    tls.handshake(asio::ssl::stream_base::server, ec);
    if (!ec) {
      std::array<char, 256> buf{};
      const std::size_t n = tls.read_some(asio::buffer(buf), ec);
      if (!ec) {
        seen_.received.assign(buf.data(), n);
        asio::write(tls, asio::buffer(buf.data(), n), ec);
      }
    }
    finished_ = true;
  }

  asio::ssl::context ctx_;
  std::string server_alpn_;
  ServerSeen seen_;
  std::atomic<bool> finished_{false};
  Upstream upstream_;  // Last: its thread starts in the constructor and uses the members above.
};

UpstreamConfig fastConfig() {
  UpstreamConfig cfg;
  cfg.connect_timeout = milliseconds{2000};
  cfg.tls_handshake_timeout = milliseconds{2000};
  return cfg;
}

struct Outcome {
  UpstreamResult result;
  std::unique_ptr<TlsStream> stream;
  bool on_strand = false;
};

/// Runs one asyncConnect to completion on a fresh io_context and returns what the handler got.
Outcome connect(UpstreamTlsConnector& connector, asio::io_context& io, const std::string& host,
                std::uint16_t port) {
  auto strand = asio::make_strand(io);
  std::optional<Outcome> outcome;
  connector.asyncConnect(strand, host, port, [&](UpstreamResult result, std::unique_ptr<TlsStream> stream) {
    outcome = Outcome{std::move(result), std::move(stream), strand.running_in_this_thread()};
  });
  io.run();
  io.restart();
  EXPECT_TRUE(outcome.has_value());
  return outcome ? std::move(*outcome) : Outcome{};
}

TEST(UpstreamTlsConnector, ConnectsAndHandsOutAVerifiedStream) {
  const TempDir tmp;
  const TestPki pki;
  TlsServer server(pki);
  asio::io_context io;
  UpstreamTlsConnector connector(fastConfig(), std::make_shared<PemBundleTrustVerifier>(pki.writeBundle(tmp)),
                                 {"http/1.1"});
  Outcome out = connect(connector, io, "localhost", server.port());
  ASSERT_EQ(out.result.status, UpstreamResult::Status::kOk) << out.result.detail;
  ASSERT_NE(out.stream, nullptr);
  EXPECT_TRUE(out.on_strand);
  EXPECT_EQ(out.result.alpn, "http/1.1");
  EXPECT_GT(out.result.connect_time.count(), 0);

  asio::write(*out.stream, asio::buffer(std::string("ping")));
  std::string echoed(4, '\0');
  asio::read(*out.stream, asio::buffer(echoed));
  EXPECT_EQ(echoed, "ping");

  const ServerSeen seen = server.seen();
  EXPECT_EQ(seen.sni, "localhost");
  EXPECT_EQ(seen.alpn_offered, std::string("\x08http/1.1"));
}

TEST(UpstreamTlsConnector, ReportsNoAlpnWhenTheOriginSelectsNone) {
  const TempDir tmp;
  const TestPki pki;
  TlsServer server(pki, "");
  asio::io_context io;
  UpstreamTlsConnector connector(fastConfig(), std::make_shared<PemBundleTrustVerifier>(pki.writeBundle(tmp)),
                                 {"http/1.1"});
  const Outcome out = connect(connector, io, "localhost", server.port());
  ASSERT_EQ(out.result.status, UpstreamResult::Status::kOk) << out.result.detail;
  EXPECT_EQ(out.result.alpn, "");
}

TEST(UpstreamTlsConnector, RejectsAnUntrustedChainAndSendsNoData) {
  const TempDir tmp;
  const TestPki pki;
  const TestPki other;
  TlsServer server(pki);
  asio::io_context io;
  UpstreamTlsConnector connector(fastConfig(), std::make_shared<PemBundleTrustVerifier>(other.writeBundle(tmp)),
                                 {"http/1.1"});
  const Outcome out = connect(connector, io, "localhost", server.port());
  EXPECT_EQ(out.result.status, UpstreamResult::Status::kVerifyFailed);
  EXPECT_FALSE(out.result.detail.empty());
  EXPECT_EQ(out.stream, nullptr);
  EXPECT_EQ(server.seen().received, "");
}

TEST(UpstreamTlsConnector, RejectsALeafForAnotherName) {
  const TempDir tmp;
  const TestPki pki("DNS:other.test");
  TlsServer server(pki);
  asio::io_context io;
  UpstreamTlsConnector connector(fastConfig(), std::make_shared<PemBundleTrustVerifier>(pki.writeBundle(tmp)),
                                 {"http/1.1"});
  const Outcome out = connect(connector, io, "localhost", server.port());
  EXPECT_EQ(out.result.status, UpstreamResult::Status::kVerifyFailed);
}

TEST(UpstreamTlsConnector, RefusesTlsBelow1_2) {
  const TempDir tmp;
  const TestPki pki;
  TlsServer server(pki, "http/1.1", TLS1_1_VERSION);
  asio::io_context io;
  UpstreamTlsConnector connector(fastConfig(), std::make_shared<PemBundleTrustVerifier>(pki.writeBundle(tmp)),
                                 {"http/1.1"});
  const Outcome out = connect(connector, io, "localhost", server.port());
  EXPECT_EQ(out.result.status, UpstreamResult::Status::kHandshakeFailed) << out.result.detail;
}

TEST(UpstreamTlsConnector, ReportsAHandshakeFailureForANonTlsServer) {
  const TempDir tmp;
  const TestPki pki;
  Upstream server([](tcp::socket& socket) {
    asio::write(socket, asio::buffer(std::string("HTTP/1.1 400 Bad Request\r\n\r\n")));
    socket.close();
  });
  asio::io_context io;
  UpstreamTlsConnector connector(fastConfig(), std::make_shared<PemBundleTrustVerifier>(pki.writeBundle(tmp)),
                                 {"http/1.1"});
  const Outcome out = connect(connector, io, "localhost", server.port());
  EXPECT_EQ(out.result.status, UpstreamResult::Status::kHandshakeFailed);
}

TEST(UpstreamTlsConnector, ReportsARefusedConnection) {
  const TempDir tmp;
  const TestPki pki;
  asio::io_context io;
  UpstreamTlsConnector connector(fastConfig(), std::make_shared<PemBundleTrustVerifier>(pki.writeBundle(tmp)),
                                 {"http/1.1"});
  const Outcome out = connect(connector, io, "127.0.0.1", test::closedPort());
  EXPECT_EQ(out.result.status, UpstreamResult::Status::kConnectFailed);
}

TEST(UpstreamTlsConnector, ReportsAHostThatDoesNotResolve) {
  const TempDir tmp;
  const TestPki pki;
  asio::io_context io;
  UpstreamTlsConnector connector(fastConfig(), std::make_shared<PemBundleTrustVerifier>(pki.writeBundle(tmp)),
                                 {"http/1.1"});
  const Outcome out = connect(connector, io, "llmfw-test.invalid", 443);
  EXPECT_EQ(out.result.status, UpstreamResult::Status::kResolveFailed) << out.result.detail;
}

TEST(UpstreamTlsConnector, TimesOutWhenTheOriginNeverAnswersTheHandshake) {
  const TempDir tmp;
  const TestPki pki;
  std::atomic<bool> release{false};
  Upstream server([&](tcp::socket&) {
    while (!release.load()) {
      std::this_thread::sleep_for(milliseconds{5});
    }
  });
  UpstreamConfig cfg = fastConfig();
  cfg.tls_handshake_timeout = milliseconds{200};
  asio::io_context io;
  UpstreamTlsConnector connector(cfg, std::make_shared<PemBundleTrustVerifier>(pki.writeBundle(tmp)), {"http/1.1"});
  const Outcome out = connect(connector, io, "localhost", server.port());
  release = true;
  EXPECT_EQ(out.result.status, UpstreamResult::Status::kTimeout);
  EXPECT_EQ(out.stream, nullptr);
}

/// Blocks in verify() until released, to hold an operation in the verification phase.
class SlowVerifier final : public UpstreamTrustVerifier {
 public:
  [[nodiscard]] VerifyResult verify(STACK_OF(X509)*, std::string_view) const override {
    while (!release.load()) {
      std::this_thread::sleep_for(milliseconds{5});
    }
    return {true, {}};
  }
  mutable std::atomic<bool> release{false};
};

TEST(UpstreamTlsConnector, TimesOutWhileVerificationIsStillRunning) {
  const TestPki pki;
  TlsServer server(pki);
  auto verifier = std::make_shared<SlowVerifier>();
  UpstreamConfig cfg = fastConfig();
  cfg.tls_handshake_timeout = milliseconds{200};
  asio::io_context io;
  UpstreamTlsConnector connector(cfg, verifier, {"http/1.1"});
  std::optional<Outcome> outcome;
  connector.asyncConnect(asio::make_strand(io), "localhost", server.port(),
                         [&](UpstreamResult result, std::unique_ptr<TlsStream> stream) {
                           outcome = Outcome{std::move(result), std::move(stream), false};
                         });
  // Let the timer fire while verify() blocks, then let verify() return.
  std::thread releaser([&] {
    std::this_thread::sleep_for(milliseconds{400});
    verifier->release = true;
  });
  io.run();
  releaser.join();
  ASSERT_TRUE(outcome.has_value());
  EXPECT_EQ(outcome->result.status, UpstreamResult::Status::kTimeout);
  EXPECT_EQ(outcome->stream, nullptr);
}

TEST(UpstreamTlsConnector, RejectsInvalidAlpnNames) {
  const TempDir tmp;
  const TestPki pki;
  auto verifier = std::make_shared<PemBundleTrustVerifier>(pki.writeBundle(tmp));
  EXPECT_THROW(UpstreamTlsConnector(fastConfig(), verifier, {""}), std::invalid_argument);
  EXPECT_THROW(UpstreamTlsConnector(fastConfig(), verifier, {std::string(256, 'a')}), std::invalid_argument);
}

}  // namespace
}  // namespace llmfw
