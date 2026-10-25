#include <gtest/gtest.h>

#include <chrono>
#include <filesystem>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include <boost/asio/executor_work_guard.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/ssl/context.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/asio/write.hpp>

#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include <unistd.h>

#include "llmfw/cert_store.hpp"
#include "llmfw/connect_handler.hpp"
#include "llmfw/listener.hpp"
#include "llmfw/setup_ca.hpp"
#include "llmfw/setup_leaf.hpp"
#include "llmfw/tls_breaker.hpp"
#include "llmfw/tls_client.hpp"
#include "llmfw/tls_server.hpp"
#include "llmfw/trust_verifier.hpp"
#include "net_test_util.hpp"

namespace llmfw {
namespace {

namespace fs = std::filesystem;
using std::chrono::milliseconds;
using test::kEstablished;
using test::readExactly;
using test::readToEnd;
using TestStream = asio::ssl::stream<tcp::socket>;

const std::string kUserAgent = "Mozilla/5.0 Claude/2.9 Electron/38";

/// A fresh temp directory (mode 0700 from mkdtemp), removed with everything in it when the object goes away.
class TempDir {
 public:
  TempDir() {
    std::string tmpl = (fs::temp_directory_path() / "llmfw-decrypt-XXXXXX").string();
    path_ = ::mkdtemp(tmpl.data());
  }
  ~TempDir() { fs::remove_all(path_); }
  TempDir(const TempDir&) = delete;
  TempDir& operator=(const TempDir&) = delete;
  [[nodiscard]] const fs::path& path() const { return path_; }

 private:
  fs::path path_;
};

/// A name-constrained CA and its four-name leaf, as llmfw-setup makes them.
struct Pki {
  setup::EphemeralCa ca;
  setup::IssuedLeaf leaf;

  explicit Pki(const std::string& name) {
    setup::CaSpec spec;
    spec.common_name = name;
    ca = setup::generateConstrainedCa(spec);
    leaf = setup::issueLeaf(ca, setup::LeafSpec{});
  }
  [[nodiscard]] fs::path writeCaBundle(const fs::path& path) const {
    const BioPtr bio(BIO_new_file(path.c_str(), "w"));
    PEM_write_bio_X509(bio.get(), ca.cert.get());
    return path;
  }
};

/// The real origin stand-in: serves TLS with its own claude.ai leaf, one thread per
/// connection. It echoes, or with `http_reply` answers each request head with it. Accepting runs on its own io_context thread, and only that
/// thread touches the acceptor.
class Origin {
 public:
  explicit Origin(const Pki& pki, std::string http_reply = {})
      : http_reply_(std::move(http_reply)), acceptor_(io_, {asio::ip::make_address("127.0.0.1"), 0}) {
    SSL_CTX_use_certificate(ctx_.native_handle(), pki.leaf.cert.get());
    SSL_CTX_use_PrivateKey(ctx_.native_handle(), pki.leaf.key.get());
    acceptNext();
    accept_thread_ = std::thread([this] { io_.run(); });
  }
  ~Origin() {
    asio::post(io_, [this] {
      boost::system::error_code ignored;
      acceptor_.close(ignored);
    });
    accept_thread_.join();
    for (std::thread& worker : workers_) {
      worker.join();
    }
  }
  Origin(const Origin&) = delete;
  Origin& operator=(const Origin&) = delete;

  [[nodiscard]] tcp::endpoint endpoint() const { return endpoint_; }

 private:
  void acceptNext() {
    acceptor_.async_accept([this](const boost::system::error_code& ec, tcp::socket socket) {
      if (ec) {
        return;  // Closed: the io_context runs out of work and its thread ends.
      }
      workers_.emplace_back([this, socket = std::move(socket)]() mutable { serve(std::move(socket)); });
      acceptNext();
    });
  }

  void serve(tcp::socket socket) {
    asio::ssl::stream<tcp::socket&> tls(socket, ctx_);
    boost::system::error_code ec;
    tls.handshake(asio::ssl::stream_base::server, ec);
    std::array<char, 4096> buf{};
    std::string request;
    while (!ec) {
      const std::size_t n = tls.read_some(asio::buffer(buf), ec);
      if (ec) {
        break;
      }
      if (http_reply_.empty()) {
        asio::write(tls, asio::buffer(buf.data(), n), ec);
        continue;
      }
      request.append(buf.data(), n);
      if (request.find("\r\n\r\n") != std::string::npos) {
        request.clear();
        asio::write(tls, asio::buffer(http_reply_), ec);
      }
    }
    tls.shutdown(ec);
  }

  std::string http_reply_;
  asio::io_context io_;
  asio::ssl::context ctx_{asio::ssl::context::tls_server};
  tcp::acceptor acceptor_;
  tcp::endpoint endpoint_ = acceptor_.local_endpoint();
  std::vector<std::thread> workers_;
  std::thread accept_thread_;
};

/// The proxy with decryption on: our leaf for clients, upstream trust limited to
/// `trusted_origin_ca`, and every upstream connection sent to `origin`.
class DecryptHarness {
 public:
  DecryptHarness(const Pki& proxy_pki, const Pki& trusted_origin_ca, tcp::endpoint origin)
      : scope_({"claude.ai", "*.claude.ai"}), origin_(origin) {
    config_.listen.port = 0;
    config_.capture.redact_headers = {"cookie", "authorization"};
    config_.listen.client_tls_breaker_cooldown = milliseconds(60'000);
    config_.upstream.connect_timeout = milliseconds(2000);
    config_.upstream.tls_handshake_timeout = milliseconds(2000);
    setup::writeLeaf(setup::IssuedLeaf{X509Ptr(X509_dup(proxy_pki.leaf.cert.get())),
                                       EvpPkeyPtr(EVP_PKEY_dup(proxy_pki.leaf.key.get()))},
                     certs_dir_.path() / "leaf.pem", certs_dir_.path() / "leaf.key");
    config_.certs.dir = certs_dir_.path();
    certs_.emplace(LeafCertStore::load(config_.certs));
    terminator_ = std::make_unique<ClientTlsTerminator>(*certs_, config_.listen.client_alpn);
    connector_ = std::make_unique<UpstreamTlsConnector>(
        config_.upstream,
        std::make_shared<PemBundleTrustVerifier>(trusted_origin_ca.writeCaBundle(certs_dir_.path() / "origin-ca.pem")),
        config_.listen.client_alpn);
    context_.certs = &*certs_;
    context_.breaker = &breaker_;
    context_.terminator = terminator_.get();
    context_.connector = connector_.get();
    context_.upstream_override = &origin_;
    listener_ = std::make_unique<Listener>(io_, config_.listen, context_);
    listener_->start();
    for (int i = 0; i < 2; ++i) {
      threads_.emplace_back([this] { io_.run(); });
    }
  }
  ~DecryptHarness() {
    listener_->stop();
    work_.reset();
    io_.stop();
    for (std::thread& t : threads_) {
      t.join();
    }
  }
  DecryptHarness(const DecryptHarness&) = delete;
  DecryptHarness& operator=(const DecryptHarness&) = delete;

  /// Connects to the proxy and sends `CONNECT authority` plus `extra` bytes.
  tcp::socket sendConnect(const std::string& authority, const std::string& extra = "") {
    tcp::socket socket(client_io_);
    socket.connect(listener_->localEndpoint());
    asio::write(socket, asio::buffer("CONNECT " + authority + " HTTP/1.1\r\nHost: " + authority +
                                     "\r\nUser-Agent: " + kUserAgent + "\r\n\r\n" + extra));
    return socket;
  }

  CaptureQueue& queue() { return queue_; }
  ProxyCounters& counters() { return counters_; }

 private:
  TempDir certs_dir_;
  ProxyConfig config_;
  HostScope scope_;
  ProxyCounters counters_;
  CaptureQueue queue_{100, 1 << 20, counters_};
  ClientClassifier classifier_{{{ClientPathTag::kClaudeCode, {"claude-cli/"}}, {ClientPathTag::kUi, {"Electron/"}}}};
  CaptureBuildContext build_{classifier_, counters_};
  TunnelRegistry tunnels_;
  std::string pac_;
  ProxyContext context_{config_, scope_, queue_, counters_, build_, tunnels_, pac_};
  tcp::endpoint origin_;
  std::optional<LeafCertStore> certs_;
  ClientTlsBreaker breaker_{milliseconds(60'000)};
  std::unique_ptr<ClientTlsTerminator> terminator_;
  std::unique_ptr<UpstreamTlsConnector> connector_;
  asio::io_context io_;
  asio::executor_work_guard<asio::io_context::executor_type> work_ = asio::make_work_guard(io_);
  std::unique_ptr<Listener> listener_;
  std::vector<std::thread> threads_;
  asio::io_context client_io_;
};

/// What Claude does after the 200: TLS with SNI claude.ai, verifying the host against `trusted_ca`.
struct TlsClient {
  asio::ssl::context ctx{asio::ssl::context::tls_client};
  std::unique_ptr<TestStream> stream;
  boost::system::error_code handshake_error;

  TlsClient(tcp::socket socket, const X509& trusted_ca) {
    X509_STORE_add_cert(SSL_CTX_get_cert_store(ctx.native_handle()), const_cast<X509*>(&trusted_ca));
    ctx.set_verify_mode(asio::ssl::verify_peer);
    const unsigned char alpn[] = "\x02h2\x08http/1.1";
    SSL_CTX_set_alpn_protos(ctx.native_handle(), alpn, sizeof alpn - 1);
    stream = std::make_unique<TestStream>(std::move(socket), ctx);
    SSL_set_tlsext_host_name(stream->native_handle(), "claude.ai");
    X509_VERIFY_PARAM_set1_host(SSL_get0_param(stream->native_handle()), "claude.ai", 0);
    stream->handshake(asio::ssl::stream_base::client, handshake_error);
  }

  /// The subject CN of the CA that issued the certificate we were shown.
  [[nodiscard]] std::string issuerName() const {
    X509* peer = SSL_get1_peer_certificate(stream->native_handle());
    char cn[256] = {};
    X509_NAME_get_text_by_NID(X509_get_issuer_name(peer), NID_commonName, cn, sizeof cn);
    X509_free(peer);
    return cn;
  }
};

TEST(DecryptPath, DecryptsAScopedConnectEndToEnd) {
  const Pki proxy_pki("llm-firewall local CA (proxy)");
  const Pki origin_pki("origin CA");
  Origin origin(origin_pki);
  DecryptHarness proxy(proxy_pki, origin_pki, origin.endpoint());

  tcp::socket socket = proxy.sendConnect("claude.ai:443");
  ASSERT_EQ(readExactly(socket, kEstablished.size()), kEstablished);
  TlsClient client(std::move(socket), *proxy_pki.ca.cert);
  ASSERT_FALSE(client.handshake_error) << client.handshake_error.message();
  EXPECT_EQ(client.issuerName(), "llm-firewall local CA (proxy)") << "the client sees our leaf";

  asio::write(*client.stream, asio::buffer(std::string("ping")));
  std::string echoed(4, '\0');
  asio::read(*client.stream, asio::buffer(echoed));
  EXPECT_EQ(echoed, "ping");
  boost::system::error_code ignored;
  client.stream->shutdown(ignored);

  const auto frame = proxy.queue().popWait(milliseconds(3000));
  ASSERT_NE(frame, nullptr);
  ASSERT_EQ(frame->capture().payload_case(), llmfw::v1::Capture::kDecrypted);
  const llmfw::v1::DecryptedConnection& decrypted = frame->capture().decrypted();
  EXPECT_EQ(decrypted.host(), "claude.ai");
  EXPECT_EQ(decrypted.alpn(), "http/1.1");
  EXPECT_EQ(decrypted.bytes_client_to_server(), 4u);
  EXPECT_EQ(decrypted.bytes_server_to_client(), 4u);
  EXPECT_GT(decrypted.upstream_connect_us(), 0u);
  EXPECT_GT(decrypted.client_handshake_us(), 0u);
  EXPECT_EQ(frame->capture().client().connect_user_agent(), kUserAgent);
  EXPECT_EQ(proxy.counters().connections_decrypted.load(), 1u);
  EXPECT_EQ(proxy.counters().http_parse_errors.load(), 1u) << "\"ping\" is not HTTP";
}

TEST(DecryptPath, RecordsEachHttpExchangeBeforeTheConnection) {
  const Pki proxy_pki("llm-firewall local CA (proxy)");
  const Pki origin_pki("origin CA");
  Origin origin(origin_pki, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\nok");
  DecryptHarness proxy(proxy_pki, origin_pki, origin.endpoint());

  tcp::socket socket = proxy.sendConnect("claude.ai:443");
  ASSERT_EQ(readExactly(socket, kEstablished.size()), kEstablished);
  TlsClient client(std::move(socket), *proxy_pki.ca.cert);
  ASSERT_FALSE(client.handshake_error) << client.handshake_error.message();
  const std::string response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\nok";
  for (const std::string target : {"/api/one?token=abc", "/api/two"}) {
    asio::write(*client.stream, asio::buffer("GET " + target +
                                             " HTTP/1.1\r\nHost: claude.ai\r\nUser-Agent: claude-cli/2\r\n"
                                             "Cookie: session=secret\r\n\r\n"));
    std::string got(response.size(), '\0');
    asio::read(*client.stream, asio::buffer(got));
    EXPECT_EQ(got, response) << "the response reaches the client unchanged";
  }
  boost::system::error_code ignored;
  client.stream->shutdown(ignored);

  for (std::uint32_t i = 0; i < 2; ++i) {
    const auto frame = proxy.queue().popWait(milliseconds(3000));
    ASSERT_NE(frame, nullptr);
    ASSERT_EQ(frame->capture().payload_case(), llmfw::v1::Capture::kHttp);
    const llmfw::v1::HttpExchange& http = frame->capture().http();
    EXPECT_EQ(frame->capture().exchange_index(), i);
    EXPECT_EQ(http.request().target(), i == 0 ? "/api/one?token=abc" : "/api/two");
    EXPECT_EQ(http.response().status(), 200u);
    EXPECT_EQ(http.response().body().total_bytes(), 2u);
    EXPECT_TRUE(http.response().body().omitted()) << "metadata_only keeps no body bytes";
    EXPECT_EQ(http.outcome(), llmfw::v1::EXCHANGE_OUTCOME_COMPLETE);
    EXPECT_EQ(frame->capture().client().path(), llmfw::v1::CLIENT_PATH_CLAUDE_CODE);
    EXPECT_EQ(frame->SerializeAsString().find("secret"), std::string::npos) << "the cookie is redacted";
  }
  const auto connection = proxy.queue().popWait(milliseconds(3000));
  ASSERT_NE(connection, nullptr);
  EXPECT_EQ(connection->capture().payload_case(), llmfw::v1::Capture::kDecrypted);
  EXPECT_EQ(connection->capture().client().path(), llmfw::v1::CLIENT_PATH_CLAUDE_CODE)
      << "classified by the User-Agent inside TLS";
  EXPECT_EQ(connection->capture().client().user_agent(), "claude-cli/2");
  EXPECT_EQ(connection->capture().client().connect_user_agent(), kUserAgent);
  EXPECT_EQ(proxy.counters().http_parse_errors.load(), 0u);
}

TEST(DecryptPath, RecordsEachWebSocketMessageAfterTheUpgrade) {
  const Pki proxy_pki("llm-firewall local CA (proxy)");
  const Pki origin_pki("origin CA");
  const std::string switching =
      "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n";
  const std::string server_frame = "\x81\x02hi";
  Origin origin(origin_pki, switching + server_frame);
  DecryptHarness proxy(proxy_pki, origin_pki, origin.endpoint());

  tcp::socket socket = proxy.sendConnect("claude.ai:443");
  ASSERT_EQ(readExactly(socket, kEstablished.size()), kEstablished);
  TlsClient client(std::move(socket), *proxy_pki.ca.cert);
  ASSERT_FALSE(client.handshake_error) << client.handshake_error.message();
  asio::write(*client.stream, asio::buffer(std::string("GET /ws?token=abc HTTP/1.1\r\nHost: claude.ai\r\n"
                                                       "Upgrade: websocket\r\nConnection: Upgrade\r\n\r\n")));
  std::string got(switching.size() + server_frame.size(), '\0');
  asio::read(*client.stream, asio::buffer(got));
  EXPECT_EQ(got, switching + server_frame);
  // "yo!" masked with the key 01 02 03 04.
  const std::string client_frame = "\x81\x83\x01\x02\x03\x04" + std::string{static_cast<char>('y' ^ 1), static_cast<char>('o' ^ 2), static_cast<char>('!' ^ 3)};
  asio::write(*client.stream, asio::buffer(client_frame));
  boost::system::error_code ignored;
  client.stream->shutdown(ignored);

  const auto upgrade = proxy.queue().popWait(milliseconds(3000));
  ASSERT_NE(upgrade, nullptr);
  ASSERT_EQ(upgrade->capture().payload_case(), llmfw::v1::Capture::kHttp);
  EXPECT_EQ(upgrade->capture().http().outcome(), llmfw::v1::EXCHANGE_OUTCOME_UPGRADED);
  // The two directions are decoded independently, so their messages can come in either order.
  std::map<llmfw::v1::Direction, llmfw::v1::WebSocketMessage> messages;
  for (int i = 0; i < 2; ++i) {
    const auto frame = proxy.queue().popWait(milliseconds(3000));
    ASSERT_NE(frame, nullptr);
    ASSERT_EQ(frame->capture().payload_case(), llmfw::v1::Capture::kWebsocket);
    EXPECT_EQ(frame->capture().websocket().upgrade_capture_id(), upgrade->capture().capture_id());
    EXPECT_EQ(frame->capture().websocket().target(), "/ws?token=abc");
    EXPECT_TRUE(frame->capture().websocket().omitted()) << "metadata_only keeps no payload";
    messages[frame->capture().websocket().direction()] = frame->capture().websocket();
  }
  EXPECT_EQ(messages[llmfw::v1::DIRECTION_SERVER_TO_CLIENT].total_bytes(), 2u);
  EXPECT_EQ(messages[llmfw::v1::DIRECTION_CLIENT_TO_SERVER].total_bytes(), 3u);
  const auto connection = proxy.queue().popWait(milliseconds(3000));
  ASSERT_NE(connection, nullptr);
  EXPECT_EQ(connection->capture().payload_case(), llmfw::v1::Capture::kDecrypted);
  EXPECT_EQ(proxy.counters().http_parse_errors.load(), 0u);
  EXPECT_EQ(proxy.counters().ws_decode_errors.load(), 0u);
}

TEST(DecryptPath, TunnelsWhenTheOriginFailsVerification) {
  const Pki proxy_pki("llm-firewall local CA (proxy)");
  const Pki origin_pki("origin CA");
  const Pki other("some other CA");
  Origin origin(origin_pki);
  DecryptHarness proxy(proxy_pki, other, origin.endpoint());

  tcp::socket socket = proxy.sendConnect("claude.ai:443");
  ASSERT_EQ(readExactly(socket, kEstablished.size()), kEstablished);
  // Blind-tunneled to the origin, so the client checks the origin's own certificate.
  TlsClient client(std::move(socket), *origin_pki.ca.cert);
  ASSERT_FALSE(client.handshake_error) << client.handshake_error.message();
  EXPECT_EQ(client.issuerName(), "origin CA");
  boost::system::error_code ignored;
  client.stream->shutdown(ignored);
  client.stream->next_layer().close(ignored);

  const auto frame = proxy.queue().popWait(milliseconds(3000));
  ASSERT_NE(frame, nullptr);
  EXPECT_EQ(frame->capture().tunnel().reason(), llmfw::v1::TUNNEL_REASON_UPSTREAM_VERIFY_FAILED);
  EXPECT_EQ(proxy.counters().tunnels_upstream_verify_failed.load(), 1u);
  EXPECT_EQ(proxy.counters().connections_decrypted.load(), 0u);
}

TEST(DecryptPath, Replies502WhenTheOriginIsUnreachable) {
  const Pki proxy_pki("llm-firewall local CA (proxy)");
  DecryptHarness proxy(proxy_pki, proxy_pki, {asio::ip::make_address("127.0.0.1"), test::closedPort()});
  tcp::socket socket = proxy.sendConnect("claude.ai:443");
  EXPECT_TRUE(readToEnd(socket).starts_with("HTTP/1.1 502 Bad Gateway\r\n"));
  EXPECT_EQ(proxy.queue().popWait(milliseconds(300)), nullptr);
}

TEST(DecryptPath, AClientThatRejectsOurCertificateIsTunneledOnRetry) {
  const Pki proxy_pki("llm-firewall local CA (proxy)");
  const Pki origin_pki("origin CA");
  Origin origin(origin_pki);
  DecryptHarness proxy(proxy_pki, origin_pki, origin.endpoint());

  {
    tcp::socket socket = proxy.sendConnect("claude.ai:443");
    ASSERT_EQ(readExactly(socket, kEstablished.size()), kEstablished);
    const TlsClient client(std::move(socket), *origin_pki.ca.cert);  // Does not trust our CA.
    EXPECT_TRUE(client.handshake_error);
  }
  // The client gives up as soon as it has sent its alert; wait for the proxy to read it.
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
  while (proxy.counters().client_tls_handshake_failures.load() == 0 && std::chrono::steady_clock::now() < deadline) {
    std::this_thread::sleep_for(milliseconds(5));
  }
  // The breaker is now open for claude.ai: the retry reaches the origin directly.
  tcp::socket socket = proxy.sendConnect("claude.ai:443");
  ASSERT_EQ(readExactly(socket, kEstablished.size()), kEstablished);
  TlsClient retry(std::move(socket), *origin_pki.ca.cert);
  ASSERT_FALSE(retry.handshake_error) << retry.handshake_error.message();
  EXPECT_EQ(retry.issuerName(), "origin CA");
  EXPECT_EQ(proxy.counters().client_tls_handshake_failures.load(), 1u);
  EXPECT_EQ(proxy.counters().tunnels_client_tls_breaker.load(), 1u);
}

TEST(DecryptPath, TunnelsAClientThatSendsBeforeThe200) {
  const Pki proxy_pki("llm-firewall local CA (proxy)");
  const Pki origin_pki("origin CA");
  Origin origin(origin_pki);
  DecryptHarness proxy(proxy_pki, origin_pki, origin.endpoint());
  tcp::socket socket = proxy.sendConnect("claude.ai:443", "early");
  ASSERT_EQ(readExactly(socket, kEstablished.size()), kEstablished);
  socket.close();
  const auto frame = proxy.queue().popWait(milliseconds(3000));
  ASSERT_NE(frame, nullptr);
  EXPECT_EQ(frame->capture().tunnel().reason(), llmfw::v1::TUNNEL_REASON_CLIENT_SENT_EARLY);
}

TEST(DecryptPath, OnlyScopedHostsCoveredByTheLeafAreDecrypted) {
  const Pki proxy_pki("llm-firewall local CA (proxy)");
  const Pki origin_pki("origin CA");
  Origin origin(origin_pki);
  DecryptHarness proxy(proxy_pki, origin_pki, origin.endpoint());
  for (const std::string authority : {"example.com:443", "a.b.claude.ai:443"}) {
    tcp::socket socket = proxy.sendConnect(authority);
    ASSERT_EQ(readExactly(socket, kEstablished.size()), kEstablished) << authority;
    socket.close();
    const auto frame = proxy.queue().popWait(milliseconds(3000));
    ASSERT_NE(frame, nullptr) << authority;
    EXPECT_EQ(frame->capture().payload_case(), llmfw::v1::Capture::kTunnel) << authority;
  }
  EXPECT_EQ(proxy.counters().tunnels_unscoped.load(), 1u);
  EXPECT_EQ(proxy.counters().tunnels_scoped_no_cert.load(), 1u);
  EXPECT_EQ(proxy.counters().connections_decrypted.load(), 0u);
}

}  // namespace
}  // namespace llmfw
