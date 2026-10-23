#include <gtest/gtest.h>

#include <filesystem>
#include <future>
#include <memory>
#include <optional>
#include <random>
#include <string>
#include <thread>

#include <boost/asio/executor_work_guard.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/ssl/context.hpp>
#include <boost/asio/ssl/error.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/write.hpp>

#include <openssl/ssl.h>

#include <unistd.h>

#include "llmfw/decrypted_relay.hpp"
#include "llmfw/setup_ca.hpp"
#include "llmfw/setup_leaf.hpp"

namespace llmfw {
namespace {

using std::chrono::milliseconds;
using TestStream = asio::ssl::stream<tcp::socket>;

/// Records what the relay reports. Calls arrive on the relay's thread; the test reads
/// the results only after closed() has resolved.
class RecordingObserver final : public RelayObserver {
 public:
  struct Seen {
    std::string client;
    std::string upstream;
    std::optional<ExchangeOutcomeTag> outcome;
    int closed_calls = 0;
  };

  explicit RecordingObserver(std::shared_ptr<Seen> seen, std::shared_ptr<std::promise<void>> closed)
      : seen_(std::move(seen)), closed_(std::move(closed)) {}

  void onClientBytes(std::span<const std::uint8_t> bytes, Clock::time_point /*at*/) override {
    seen_->client.append(reinterpret_cast<const char*>(bytes.data()), bytes.size());
  }
  void onUpstreamBytes(std::span<const std::uint8_t> bytes, Clock::time_point /*at*/) override {
    seen_->upstream.append(reinterpret_cast<const char*>(bytes.data()), bytes.size());
  }
  void onClosed(ExchangeOutcomeTag unfinished) override {
    seen_->outcome = unfinished;
    if (++seen_->closed_calls == 1) {
      closed_->set_value();
    }
  }

 private:
  std::shared_ptr<Seen> seen_;
  std::shared_ptr<std::promise<void>> closed_;
};

/// A recording observer plus what it saw, for one relay.
struct Observed {
  std::shared_ptr<RecordingObserver::Seen> seen = std::make_shared<RecordingObserver::Seen>();
  std::shared_ptr<std::promise<void>> closed = std::make_shared<std::promise<void>>();
  std::future<void> closed_future = closed->get_future();

  std::unique_ptr<RelayObserver> observer() { return std::make_unique<RecordingObserver>(seen, closed); }
  /// Waits for onClosed and returns what was seen.
  const RecordingObserver::Seen& wait() {
    EXPECT_EQ(closed_future.wait_for(std::chrono::seconds(3)), std::future_status::ready);
    return *seen;
  }
};

/// The relay's world: shared objects, TLS contexts, the relay's io_context on its own
/// thread, and the test's own io_context for blocking client and origin streams.
class Harness {
 public:
  explicit Harness(milliseconds idle = milliseconds(5000)) {
    config_.listen.idle_timeout = idle;
    // Any certificate will do: the test's TLS clients do not verify it.
    setup::CaSpec spec;
    spec.common_name = "llm-firewall local CA (relay test)";
    const setup::EphemeralCa ca = setup::generateConstrainedCa(spec);
    const setup::IssuedLeaf leaf = setup::issueLeaf(ca, setup::LeafSpec{});
    SSL_CTX_use_certificate(server_ctx_.native_handle(), leaf.cert.get());
    SSL_CTX_use_PrivateKey(server_ctx_.native_handle(), leaf.key.get());
    client_ctx_.set_verify_mode(asio::ssl::verify_none);
    thread_ = std::thread([this] { io_.run(); });
  }
  ~Harness() {
    work_.reset();
    io_.stop();
    thread_.join();
  }
  Harness(const Harness&) = delete;
  Harness& operator=(const Harness&) = delete;

  /// Handshakes test client <-> relay (client side) and relay (upstream side) <-> test
  /// origin, then starts a relay between the two relay-side streams.
  std::shared_ptr<DecryptedRelay> open(TestStream& client, TestStream& origin,
                                       std::unique_ptr<RelayObserver> observer = nullptr) {
    auto strand = asio::make_strand(io_);
    auto relay_client = std::make_unique<TlsStream>(strand, server_ctx_);
    auto relay_upstream = std::make_unique<TlsStream>(strand, client_ctx_);
    connect(client.next_layer(), relay_client->next_layer());
    connect(origin.next_layer(), relay_upstream->next_layer());

    std::promise<void> client_side;
    std::promise<void> upstream_side;
    relay_client->async_handshake(asio::ssl::stream_base::server,
                                  [&](const boost::system::error_code& ec) {
                                    EXPECT_FALSE(ec) << ec.message();
                                    client_side.set_value();
                                  });
    relay_upstream->async_handshake(asio::ssl::stream_base::client,
                                    [&](const boost::system::error_code& ec) {
                                      EXPECT_FALSE(ec) << ec.message();
                                      upstream_side.set_value();
                                    });
    std::thread origin_handshake([&] { origin.handshake(asio::ssl::stream_base::server); });
    client.handshake(asio::ssl::stream_base::client);
    origin_handshake.join();
    client_side.get_future().wait();
    upstream_side.get_future().wait();

    DecryptedConnectionInfo info;
    info.connection_id = 7;
    info.host = "claude.ai";
    info.port = 443;
    info.alpn = "http/1.1";
    info.connect_user_agent = "Claude/2.9 Electron/38";
    info.started = Clock::now();
    info.started_unix_us = 1'790'000'000'000'000;
    info.upstream_connect = std::chrono::microseconds(1500);
    info.client_handshake = std::chrono::microseconds(700);
    auto relay = std::make_shared<DecryptedRelay>(std::move(relay_client), std::move(relay_upstream), info, context_,
                                                  std::move(observer));
    relay->start();
    return relay;
  }

  [[nodiscard]] TestStream newClient() { return TestStream(test_io_, client_ctx_); }
  [[nodiscard]] TestStream newOrigin() { return TestStream(test_io_, server_ctx_); }
  CaptureQueue& queue() { return queue_; }
  ProxyCounters& counters() { return counters_; }
  TunnelRegistry& tunnels() { return tunnels_; }

 private:
  void connect(tcp::socket& test_side, tcp::socket& relay_side) {
    tcp::acceptor acceptor(test_io_, {asio::ip::make_address("127.0.0.1"), 0});
    relay_side.connect(acceptor.local_endpoint());
    acceptor.accept(test_side);
  }

  ProxyConfig config_;
  HostScope scope_{{}};
  ProxyCounters counters_;
  CaptureQueue queue_{100, 1 << 22, counters_};
  ClientClassifier classifier_{{{ClientPathTag::kUi, {"Electron/"}}}};
  CaptureBuildContext build_{classifier_, counters_};
  TunnelRegistry tunnels_;
  std::string pac_;
  ProxyContext context_{config_, scope_, queue_, counters_, build_, tunnels_, pac_};
  asio::ssl::context server_ctx_{asio::ssl::context::tls_server};
  asio::ssl::context client_ctx_{asio::ssl::context::tls_client};
  asio::io_context io_;
  asio::executor_work_guard<asio::io_context::executor_type> work_ = asio::make_work_guard(io_);
  std::thread thread_;
  asio::io_context test_io_;
};

std::string readExactly(TestStream& stream, std::size_t n) {
  std::string out(n, '\0');
  asio::read(stream, asio::buffer(out));
  return out;
}

/// Reads until the stream ends and returns how it ended.
boost::system::error_code readUntilEnd(TestStream& stream) {
  std::array<char, 4096> buf{};
  boost::system::error_code ec;
  while (!ec) {
    (void)stream.read_some(asio::buffer(buf), ec);
  }
  return ec;
}

TEST(DecryptedRelay, RelaysBothWaysAndCapturesOnClose) {
  Harness h;
  TestStream client = h.newClient();
  TestStream origin = h.newOrigin();
  h.open(client, origin);

  asio::write(client, asio::buffer(std::string("hello")));
  EXPECT_EQ(readExactly(origin, 5), "hello");
  asio::write(origin, asio::buffer(std::string("world!")));
  EXPECT_EQ(readExactly(client, 6), "world!");

  // The client's close_notify reaches the origin as a clean end, not a truncation.
  std::thread client_close([&] {
    boost::system::error_code ignored;
    client.shutdown(ignored);
  });
  EXPECT_EQ(readUntilEnd(origin), asio::error::eof);
  boost::system::error_code ignored;
  origin.shutdown(ignored);
  client_close.join();

  const auto frame = h.queue().popWait(milliseconds(2000));
  ASSERT_NE(frame, nullptr);
  ASSERT_EQ(frame->capture().payload_case(), llmfw::v1::Capture::kDecrypted);
  const llmfw::v1::DecryptedConnection& decrypted = frame->capture().decrypted();
  EXPECT_EQ(frame->capture().connection_id(), 7u);
  EXPECT_EQ(frame->capture().client().path(), llmfw::v1::CLIENT_PATH_UI);
  EXPECT_EQ(decrypted.host(), "claude.ai");
  EXPECT_EQ(decrypted.alpn(), "http/1.1");
  EXPECT_EQ(decrypted.bytes_client_to_server(), 5u);
  EXPECT_EQ(decrypted.bytes_server_to_client(), 6u);
  EXPECT_EQ(decrypted.upstream_connect_us(), 1500u);
  EXPECT_EQ(decrypted.client_handshake_us(), 700u);
  EXPECT_GT(decrypted.duration_us(), 0u);
  EXPECT_EQ(h.counters().connections_decrypted.load(), 1u);
  EXPECT_EQ(h.tunnels().size(), 0u);
}

TEST(DecryptedRelay, PassesTheOriginsCloseNotifyToTheClient) {
  Harness h;
  TestStream client = h.newClient();
  TestStream origin = h.newOrigin();
  h.open(client, origin);

  std::thread origin_close([&] {
    asio::write(origin, asio::buffer(std::string("bye")));
    boost::system::error_code ignored;
    origin.shutdown(ignored);
  });
  EXPECT_EQ(readExactly(client, 3), "bye");
  EXPECT_EQ(readUntilEnd(client), asio::error::eof) << "a clean TLS close, not a truncation";
  boost::system::error_code ignored;
  client.shutdown(ignored);
  origin_close.join();
  ASSERT_NE(h.queue().popWait(milliseconds(2000)), nullptr);
}

TEST(DecryptedRelay, ATruncatedOriginTruncatesTheClient) {
  Harness h;
  TestStream client = h.newClient();
  TestStream origin = h.newOrigin();
  h.open(client, origin);
  asio::write(origin, asio::buffer(std::string("partial")));
  EXPECT_EQ(readExactly(client, 7), "partial");
  origin.lowest_layer().close();  // TCP close with no close_notify.
  EXPECT_EQ(readUntilEnd(client), asio::ssl::error::stream_truncated);
  ASSERT_NE(h.queue().popWait(milliseconds(2000)), nullptr);
}

TEST(DecryptedRelay, RelaysLargeTransfersByteForByte) {
  Harness h;
  TestStream client = h.newClient();
  TestStream origin = h.newOrigin();
  h.open(client, origin);
  std::mt19937 rng(42);
  std::string up(300'000, '\0');
  std::string down(500'000, '\0');
  for (char& c : up) c = static_cast<char>(rng());
  for (char& c : down) c = static_cast<char>(rng());

  std::string origin_got;
  std::thread origin_side([&] {
    origin_got = readExactly(origin, up.size());
    asio::write(origin, asio::buffer(down));
  });
  asio::write(client, asio::buffer(up));
  EXPECT_EQ(readExactly(client, down.size()), down);
  origin_side.join();
  EXPECT_EQ(origin_got, up);

  origin.lowest_layer().close();
  const auto frame = h.queue().popWait(milliseconds(2000));
  ASSERT_NE(frame, nullptr);
  EXPECT_EQ(frame->capture().decrypted().bytes_client_to_server(), up.size());
  EXPECT_EQ(frame->capture().decrypted().bytes_server_to_client(), down.size());
}

TEST(DecryptedRelay, IdleTimeoutClosesAndCaptures) {
  Harness h(milliseconds(200));
  TestStream client = h.newClient();
  TestStream origin = h.newOrigin();
  h.open(client, origin);
  const auto start = Clock::now();
  EXPECT_TRUE(readUntilEnd(client));
  EXPECT_LT(Clock::now() - start, milliseconds(3000));
  ASSERT_NE(h.queue().popWait(milliseconds(2000)), nullptr);
}

TEST(DecryptedRelay, CloseFromAnotherThreadStillCaptures) {
  Harness h;
  TestStream client = h.newClient();
  TestStream origin = h.newOrigin();
  const auto relay = h.open(client, origin);
  relay->close();
  EXPECT_TRUE(readUntilEnd(client));
  EXPECT_TRUE(readUntilEnd(origin));
  ASSERT_NE(h.queue().popWait(milliseconds(2000)), nullptr);
}

TEST(DecryptedRelay, ClosesWithoutACaptureWhenShutdownHasBegun) {
  Harness h;
  h.tunnels().closeAll([] {});
  TestStream client = h.newClient();
  TestStream origin = h.newOrigin();
  h.open(client, origin);
  EXPECT_TRUE(readUntilEnd(client));
  EXPECT_EQ(h.queue().popWait(milliseconds(300)), nullptr);
  EXPECT_EQ(h.counters().connections_decrypted.load(), 0u);
}

TEST(DecryptedRelay, TheObserverSeesForwardedBytesAndTheClientsEnd) {
  Harness h;
  TestStream client = h.newClient();
  TestStream origin = h.newOrigin();
  Observed observed;
  h.open(client, origin, observed.observer());

  asio::write(client, asio::buffer(std::string("GET / HTTP/1.1\r\n")));
  EXPECT_EQ(readExactly(origin, 16), "GET / HTTP/1.1\r\n");
  asio::write(origin, asio::buffer(std::string("HTTP/1.1 200")));
  EXPECT_EQ(readExactly(client, 12), "HTTP/1.1 200");
  client.lowest_layer().close();

  const RecordingObserver::Seen& seen = observed.wait();
  EXPECT_EQ(seen.client, "GET / HTTP/1.1\r\n");
  EXPECT_EQ(seen.upstream, "HTTP/1.1 200");
  EXPECT_EQ(seen.outcome, ExchangeOutcomeTag::kClientAborted);
  EXPECT_EQ(seen.closed_calls, 1);
  ASSERT_NE(h.queue().popWait(milliseconds(2000)), nullptr);
}

TEST(DecryptedRelay, TheObserverHearsWhenTheOriginEnds) {
  Harness h;
  TestStream client = h.newClient();
  TestStream origin = h.newOrigin();
  Observed observed;
  h.open(client, origin, observed.observer());
  std::thread origin_close([&] {
    asio::write(origin, asio::buffer(std::string("bye")));
    boost::system::error_code ignored;
    origin.shutdown(ignored);
  });
  EXPECT_EQ(readExactly(client, 3), "bye");
  boost::system::error_code ignored;
  client.shutdown(ignored);
  origin_close.join();
  EXPECT_EQ(observed.wait().outcome, ExchangeOutcomeTag::kUpstreamAborted);
  EXPECT_EQ(observed.seen->upstream, "bye");
}

TEST(DecryptedRelay, TheObserverHearsAnIdleTimeout) {
  Harness h(milliseconds(200));
  TestStream client = h.newClient();
  TestStream origin = h.newOrigin();
  Observed observed;
  h.open(client, origin, observed.observer());
  EXPECT_EQ(observed.wait().outcome, ExchangeOutcomeTag::kTimeout);
}

TEST(DecryptedRelay, TheObserverSeesLargeTransfersWhole) {
  Harness h;
  TestStream client = h.newClient();
  TestStream origin = h.newOrigin();
  Observed observed;
  h.open(client, origin, observed.observer());
  std::mt19937 rng(7);
  std::string up(200'000, '\0');
  for (char& c : up) c = static_cast<char>(rng());
  asio::write(client, asio::buffer(up));
  EXPECT_EQ(readExactly(origin, up.size()), up);
  origin.lowest_layer().close();
  EXPECT_EQ(observed.wait().client, up);
}

}  // namespace
}  // namespace llmfw
