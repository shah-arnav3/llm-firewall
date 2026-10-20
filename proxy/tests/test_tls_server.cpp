#include <gtest/gtest.h>

#include <filesystem>
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

#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include <unistd.h>

#include "llmfw/cert_store.hpp"
#include "llmfw/setup_ca.hpp"
#include "llmfw/setup_leaf.hpp"
#include "llmfw/tls_server.hpp"

namespace llmfw {
namespace {

namespace fs = std::filesystem;
using std::chrono::milliseconds;

/// A fresh temp directory (mode 0700 from mkdtemp), removed with everything in it when the object goes away.
class TempDir {
 public:
  TempDir() {
    std::string tmpl = (fs::temp_directory_path() / "llmfw-tlss-XXXXXX").string();
    path_ = ::mkdtemp(tmpl.data());
  }
  ~TempDir() { fs::remove_all(path_); }
  TempDir(const TempDir&) = delete;
  TempDir& operator=(const TempDir&) = delete;
  [[nodiscard]] const fs::path& path() const { return path_; }

 private:
  fs::path path_;
};

/// The production CA and leaf, written and loaded the way the proxy loads them.
struct TestCerts {
  TempDir dir;
  setup::EphemeralCa ca;
  std::optional<LeafCertStore> store;

  TestCerts() {
    setup::CaSpec spec;
    spec.common_name = "llm-firewall local CA (tls server test)";
    ca = setup::generateConstrainedCa(spec);
    setup::writeLeaf(setup::issueLeaf(ca, setup::LeafSpec{}), dir.path() / "leaf.pem", dir.path() / "leaf.key");
    CertConfig cfg;
    cfg.dir = dir.path();
    store.emplace(LeafCertStore::load(cfg));
  }
};

struct ClientOptions {
  std::optional<std::string> sni = "claude.ai";
  std::string alpn_wire = std::string("\x02h2\x08http/1.1", 12);  ///< Empty: offer no ALPN.
  bool trust_ca = true;
  int max_version = 0;
  bool send_nothing = false;  ///< Connect, then wait without starting TLS.
};

struct ClientSeen {
  bool handshake_ok = false;
  std::string alpn;
  std::string echoed;
};

/// Runs a TLS client against 127.0.0.1:port on its own thread.
class Client {
 public:
  Client(std::uint16_t port, const X509& ca, ClientOptions options) {
    thread_ = std::thread([this, port, &ca, options] { run(port, ca, options); });
  }
  ~Client() {
    if (thread_.joinable()) {
      thread_.join();
    }
  }
  Client(const Client&) = delete;
  Client& operator=(const Client&) = delete;
  [[nodiscard]] ClientSeen seen() {
    thread_.join();
    return seen_;
  }

 private:
  void run(std::uint16_t port, const X509& ca, const ClientOptions& options) {
    asio::io_context io;
    asio::ssl::context ctx(asio::ssl::context::tls_client);
    SSL_CTX* raw = ctx.native_handle();
    if (options.trust_ca) {
      X509_STORE_add_cert(SSL_CTX_get_cert_store(raw), const_cast<X509*>(&ca));
    }
    if (options.max_version != 0) {
      SSL_CTX_set_security_level(raw, 0);
      SSL_CTX_set_min_proto_version(raw, 0);
      SSL_CTX_set_max_proto_version(raw, options.max_version);
    }
    ctx.set_verify_mode(asio::ssl::verify_peer);
    if (!options.alpn_wire.empty()) {
      SSL_CTX_set_alpn_protos(raw, reinterpret_cast<const unsigned char*>(options.alpn_wire.data()),
                              static_cast<unsigned int>(options.alpn_wire.size()));
    }
    asio::ssl::stream<tcp::socket> tls(io, ctx);
    boost::system::error_code ec;
    tls.lowest_layer().connect({asio::ip::make_address("127.0.0.1"), port}, ec);
    if (ec) {
      return;
    }
    if (options.send_nothing) {
      std::array<char, 1> byte{};
      tls.next_layer().read_some(asio::buffer(byte), ec);  // Until the server gives up.
      return;
    }
    if (options.sni) {
      SSL_set_tlsext_host_name(tls.native_handle(), options.sni->c_str());
      X509_VERIFY_PARAM_set1_host(SSL_get0_param(tls.native_handle()), "claude.ai", 0);
    }
    tls.handshake(asio::ssl::stream_base::client, ec);
    if (ec) {
      return;
    }
    seen_.handshake_ok = true;
    const unsigned char* alpn = nullptr;
    unsigned int alpn_length = 0;
    SSL_get0_alpn_selected(tls.native_handle(), &alpn, &alpn_length);
    seen_.alpn.assign(reinterpret_cast<const char*>(alpn), alpn_length);
    asio::write(tls, asio::buffer(std::string("ping")), ec);
    seen_.echoed.resize(4);
    asio::read(tls, asio::buffer(seen_.echoed), ec);
  }

  ClientSeen seen_;
  std::thread thread_;
};

struct ServerOutcome {
  boost::system::error_code ec;
  ClientTlsResult result;
  bool on_strand = false;
};

/// Accepts one connection, runs asyncHandshake for `expected_host`, and echoes 4 bytes on success.
ServerOutcome serveOne(ClientTlsTerminator& terminator, const X509& ca, ClientOptions options,
                       const std::string& expected_host = "claude.ai", milliseconds timeout = milliseconds{2000},
                       ClientSeen* client_seen = nullptr) {
  asio::io_context io;
  auto strand = asio::make_strand(io);
  tcp::acceptor acceptor(io, {asio::ip::make_address("127.0.0.1"), 0});
  Client client(acceptor.local_endpoint().port(), ca, options);
  std::unique_ptr<TlsStream> stream;
  std::string buffer(4, '\0');
  ServerOutcome outcome;
  acceptor.async_accept(strand, [&](const boost::system::error_code& accept_ec, tcp::socket socket) {
    ASSERT_FALSE(accept_ec);
    stream = std::make_unique<TlsStream>(std::move(socket), terminator.context());
    terminator.asyncHandshake(
        *stream, expected_host, timeout, [&](const boost::system::error_code& ec, ClientTlsResult result) {
          outcome = {ec, std::move(result), strand.running_in_this_thread()};
          if (ec) {
            boost::system::error_code ignored;
            stream->lowest_layer().close(ignored);
            return;
          }
          asio::async_read(*stream, asio::buffer(buffer), [&](const boost::system::error_code& read_ec, std::size_t) {
            if (!read_ec) {
              asio::write(*stream, asio::buffer(buffer));
            }
            boost::system::error_code ignored;
            stream->lowest_layer().close(ignored);
          });
        });
  });
  io.run();
  const ClientSeen seen = client.seen();
  if (client_seen != nullptr) {
    *client_seen = seen;
  }
  return outcome;
}

TEST(ClientTlsTerminator, CompletesTheHandshakeWithOurLeafAndHttp11) {
  TestCerts certs;
  ClientTlsTerminator terminator(*certs.store, {"http/1.1"});
  ClientSeen client;
  const ServerOutcome out = serveOne(terminator, *certs.ca.cert, {}, "claude.ai", milliseconds{2000}, &client);
  ASSERT_FALSE(out.ec) << out.ec.message();
  EXPECT_TRUE(out.on_strand);
  EXPECT_EQ(out.result.sni, "claude.ai");
  EXPECT_EQ(out.result.alpn, "http/1.1");
  EXPECT_FALSE(out.result.client_rejected_cert);
  EXPECT_GT(out.result.handshake_time.count(), 0);
  EXPECT_TRUE(client.handshake_ok) << "the client verified our leaf for claude.ai";
  EXPECT_EQ(client.alpn, "http/1.1");
  EXPECT_EQ(client.echoed, "ping");
}

TEST(ClientTlsTerminator, NegotiatesNoAlpnWhenTheClientOffersNone) {
  TestCerts certs;
  ClientTlsTerminator terminator(*certs.store, {"http/1.1"});
  ClientOptions options;
  options.alpn_wire.clear();
  const ServerOutcome out = serveOne(terminator, *certs.ca.cert, options);
  ASSERT_FALSE(out.ec) << out.ec.message();
  EXPECT_EQ(out.result.alpn, "");
}

TEST(ClientTlsTerminator, NeverSelectsAProtocolWeDidNotConfigure) {
  TestCerts certs;
  ClientTlsTerminator terminator(*certs.store, {"http/1.1"});
  ClientOptions options;
  options.alpn_wire = std::string("\x02h2", 3);
  const ServerOutcome out = serveOne(terminator, *certs.ca.cert, options);
  ASSERT_FALSE(out.ec) << out.ec.message();
  EXPECT_EQ(out.result.alpn, "");
}

TEST(ClientTlsTerminator, AcceptsAnSniThatNormalizesToTheConnectHost) {
  TestCerts certs;
  ClientTlsTerminator terminator(*certs.store, {"http/1.1"});
  ClientOptions options;
  options.sni = "Claude.AI.";
  const ServerOutcome out = serveOne(terminator, *certs.ca.cert, options);
  ASSERT_FALSE(out.ec) << out.ec.message();
  EXPECT_EQ(out.result.sni, "claude.ai");
}

TEST(ClientTlsTerminator, RejectsAnSniForAnotherHost) {
  TestCerts certs;
  ClientTlsTerminator terminator(*certs.store, {"http/1.1"});
  ClientOptions options;
  options.sni = "api.claude.ai";
  ClientSeen client;
  const ServerOutcome out = serveOne(terminator, *certs.ca.cert, options, "claude.ai", milliseconds{2000}, &client);
  EXPECT_TRUE(out.ec);
  EXPECT_EQ(out.result.sni, "api.claude.ai");
  EXPECT_FALSE(out.result.client_rejected_cert);
  EXPECT_FALSE(client.handshake_ok);
}

TEST(ClientTlsTerminator, RejectsAClientHelloWithoutSni) {
  TestCerts certs;
  ClientTlsTerminator terminator(*certs.store, {"http/1.1"});
  ClientOptions options;
  options.sni.reset();
  const ServerOutcome out = serveOne(terminator, *certs.ca.cert, options);
  EXPECT_TRUE(out.ec);
  EXPECT_EQ(out.result.sni, "");
  EXPECT_FALSE(out.result.client_rejected_cert);
}

TEST(ClientTlsTerminator, ReportsAClientThatRejectsOurCertificate) {
  TestCerts certs;
  ClientTlsTerminator terminator(*certs.store, {"http/1.1"});
  ClientOptions options;
  options.trust_ca = false;
  const ServerOutcome out = serveOne(terminator, *certs.ca.cert, options);
  EXPECT_TRUE(out.ec);
  EXPECT_TRUE(out.result.client_rejected_cert) << out.ec.message();
}

TEST(ClientTlsTerminator, RefusesTlsBelow1_2) {
  TestCerts certs;
  ClientTlsTerminator terminator(*certs.store, {"http/1.1"});
  ClientOptions options;
  options.max_version = TLS1_1_VERSION;
  const ServerOutcome out = serveOne(terminator, *certs.ca.cert, options);
  EXPECT_TRUE(out.ec);
  EXPECT_FALSE(out.result.client_rejected_cert);
}

TEST(ClientTlsTerminator, TimesOutAClientThatSendsNothing) {
  TestCerts certs;
  ClientTlsTerminator terminator(*certs.store, {"http/1.1"});
  ClientOptions options;
  options.send_nothing = true;
  const ServerOutcome out = serveOne(terminator, *certs.ca.cert, options, "claude.ai", milliseconds{200});
  EXPECT_EQ(out.ec, asio::error::timed_out);
  EXPECT_FALSE(out.result.client_rejected_cert);
}

TEST(ClientTlsTerminator, RejectsInvalidAlpnNames) {
  TestCerts certs;
  EXPECT_THROW(ClientTlsTerminator(*certs.store, {""}), std::invalid_argument);
}

}  // namespace
}  // namespace llmfw
