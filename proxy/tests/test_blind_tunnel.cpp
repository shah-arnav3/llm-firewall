#include <gtest/gtest.h>

#include <functional>
#include <string>
#include <thread>

#include <boost/asio/executor_work_guard.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/write.hpp>

#include "llmfw/blind_tunnel.hpp"

namespace llmfw {
namespace {

using std::chrono::milliseconds;
namespace error = asio::error;

const std::string kEstablished = "HTTP/1.1 200 Connection Established\r\n\r\n";

/// A loopback upstream server that handles one connection on its own thread.
class Upstream {
 public:
  using Handler = std::function<void(tcp::socket&)>;

  explicit Upstream(Handler handler) : acceptor_(io_, {asio::ip::make_address("127.0.0.1"), 0}) {
    thread_ = std::thread([this, handler = std::move(handler)] {
      boost::system::error_code ec;
      tcp::socket socket = acceptor_.accept(ec);
      if (!ec) {
        handler(socket);
      }
    });
  }
  ~Upstream() {
    boost::system::error_code ignored;
    acceptor_.close(ignored);
    thread_.join();
  }
  Upstream(const Upstream&) = delete;
  Upstream& operator=(const Upstream&) = delete;

  [[nodiscard]] std::uint16_t port() const { return acceptor_.local_endpoint().port(); }

 private:
  asio::io_context io_;
  tcp::acceptor acceptor_;
  std::thread thread_;
};

/// Echoes until the peer stops sending, then closes.
void echo(tcp::socket& socket) {
  std::array<char, 4096> buf{};
  boost::system::error_code ec;
  while (true) {
    const std::size_t n = socket.read_some(asio::buffer(buf), ec);
    if (ec) {
      break;
    }
    asio::write(socket, asio::buffer(buf.data(), n), ec);
  }
  socket.close(ec);
}

/// Reads everything until the peer stops sending, then replies with it reversed and closes.
void replyAfterEof(tcp::socket& socket) {
  std::string received;
  boost::system::error_code ec;
  asio::read(socket, asio::dynamic_buffer(received), ec);
  const std::string reply(received.rbegin(), received.rend());
  asio::write(socket, asio::buffer(reply), ec);
  socket.close(ec);
}

/// A port nothing is listening on.
std::uint16_t closedPort() {
  asio::io_context io;
  tcp::acceptor acceptor(io, {asio::ip::make_address("127.0.0.1"), 0});
  return acceptor.local_endpoint().port();
}

/// The proxy side: shared objects, an io_context on its own thread, and a way to get
/// a connected (client, proxy-side) socket pair.
class Harness {
 public:
  explicit Harness(milliseconds idle = milliseconds(5000), milliseconds connect = milliseconds(2000)) {
    config_.listen.idle_timeout = idle;
    config_.upstream.connect_timeout = connect;
    work_thread_ = std::thread([this] { io_.run(); });
  }
  ~Harness() {
    work_.reset();
    io_.stop();
    work_thread_.join();
  }
  Harness(const Harness&) = delete;
  Harness& operator=(const Harness&) = delete;

  /// Connects a blocking client socket and starts a tunnel for its proxy side.
  std::shared_ptr<BlindTunnel> open(tcp::socket& client, std::uint16_t upstream_port,
                                    TunnelReasonTag reason = TunnelReasonTag::kUnscopedHost,
                                    std::string leftover = "", std::string host = "127.0.0.1") {
    tcp::acceptor acceptor(client_io_, {asio::ip::make_address("127.0.0.1"), 0});
    client.connect(acceptor.local_endpoint());
    tcp::socket proxy_side(asio::make_strand(io_));
    acceptor.accept(proxy_side);
    auto tunnel = std::make_shared<BlindTunnel>(std::move(proxy_side), 1, std::move(host), upstream_port, reason,
                                                "Claude/2.9 Electron/38", context_,
                                                std::vector<std::uint8_t>(leftover.begin(), leftover.end()));
    tunnel->start();
    return tunnel;
  }

  [[nodiscard]] tcp::socket newClient() { return tcp::socket(client_io_); }
  CaptureQueue& queue() { return queue_; }
  ProxyCounters& counters() { return counters_; }

 private:
  ProxyConfig config_;
  HostScope scope_{{}};
  ProxyCounters counters_;
  CaptureQueue queue_{100, 1 << 20, counters_};
  ClientClassifier classifier_{{{ClientPathTag::kUi, {"Electron/"}}}};
  CaptureBuildContext build_{classifier_, counters_};
  ProxyContext context_{config_, scope_, queue_, counters_, build_};
  asio::io_context io_;
  asio::executor_work_guard<asio::io_context::executor_type> work_ = asio::make_work_guard(io_);
  std::thread work_thread_;
  asio::io_context client_io_;
};

std::string readExactly(tcp::socket& socket, std::size_t n) {
  std::string out(n, '\0');
  asio::read(socket, asio::buffer(out));
  return out;
}

/// Reads until the peer closes, returning everything read.
std::string readToEnd(tcp::socket& socket) {
  std::string out;
  boost::system::error_code ec;
  asio::read(socket, asio::dynamic_buffer(out), ec);
  return out;
}

TEST(BlindTunnel, RelaysBothWaysAndCapturesOnClose) {
  Harness h;
  Upstream upstream(echo);
  tcp::socket client = h.newClient();
  h.open(client, upstream.port(), TunnelReasonTag::kUnscopedHost, "hello");

  EXPECT_EQ(readExactly(client, kEstablished.size()), kEstablished);
  EXPECT_EQ(readExactly(client, 5), "hello") << "leftover bytes must be forwarded first";
  asio::write(client, asio::buffer(std::string("world!")));
  EXPECT_EQ(readExactly(client, 6), "world!");
  client.shutdown(tcp::socket::shutdown_send);
  EXPECT_EQ(readToEnd(client), "");

  const auto frame = h.queue().popWait(milliseconds(2000));
  ASSERT_NE(frame, nullptr);
  const llmfw::v1::TunnelSummary& tunnel = frame->capture().tunnel();
  EXPECT_EQ(tunnel.host(), "127.0.0.1");
  EXPECT_EQ(tunnel.port(), upstream.port());
  EXPECT_EQ(tunnel.reason(), llmfw::v1::TUNNEL_REASON_UNSCOPED_HOST);
  EXPECT_EQ(tunnel.bytes_client_to_server(), 11u);
  EXPECT_EQ(tunnel.bytes_server_to_client(), 11u);
  EXPECT_GT(tunnel.duration_us(), 0u);
  EXPECT_EQ(frame->capture().client().path(), llmfw::v1::CLIENT_PATH_UI);
  EXPECT_EQ(h.counters().tunnels_unscoped.load(), 1u);
}

TEST(BlindTunnel, PassesHalfCloseThrough) {
  Harness h;
  Upstream upstream(replyAfterEof);
  tcp::socket client = h.newClient();
  h.open(client, upstream.port());
  EXPECT_EQ(readExactly(client, kEstablished.size()), kEstablished);
  asio::write(client, asio::buffer(std::string("abc")));
  client.shutdown(tcp::socket::shutdown_send);
  // The upstream only replies after it sees our EOF, so this proves the half-close
  // reached it while the reply direction stayed open.
  EXPECT_EQ(readToEnd(client), "cba");
  ASSERT_NE(h.queue().popWait(milliseconds(2000)), nullptr);
}

TEST(BlindTunnel, Replies502WhenUpstreamRefusesAndCapturesNothing) {
  Harness h;
  tcp::socket client = h.newClient();
  h.open(client, closedPort());
  EXPECT_EQ(readToEnd(client), "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
  EXPECT_EQ(h.queue().popWait(milliseconds(300)), nullptr);
}

TEST(BlindTunnel, Replies502WhenHostDoesNotResolve) {
  Harness h;
  tcp::socket client = h.newClient();
  h.open(client, 443, TunnelReasonTag::kUnscopedHost, "", "does-not-exist.invalid");
  EXPECT_TRUE(readToEnd(client).starts_with("HTTP/1.1 502 Bad Gateway"));
}

TEST(BlindTunnel, Replies502WhenConnectTimesOut) {
  Harness h(milliseconds(5000), milliseconds(200));
  tcp::socket client = h.newClient();
  const auto start = Clock::now();
  h.open(client, 9, TunnelReasonTag::kUnscopedHost, "", "192.0.2.1");  // TEST-NET-1: never answers.
  EXPECT_TRUE(readToEnd(client).starts_with("HTTP/1.1 502 Bad Gateway"));
  EXPECT_LT(Clock::now() - start, milliseconds(3000));
}

TEST(BlindTunnel, IdleTimeoutClosesAndCaptures) {
  Harness h(milliseconds(200));
  Upstream upstream(echo);
  tcp::socket client = h.newClient();
  h.open(client, upstream.port());
  EXPECT_EQ(readExactly(client, kEstablished.size()), kEstablished);
  const auto start = Clock::now();
  EXPECT_EQ(readToEnd(client), "");
  EXPECT_LT(Clock::now() - start, milliseconds(3000));
  ASSERT_NE(h.queue().popWait(milliseconds(2000)), nullptr);
}

TEST(BlindTunnel, CloseFromAnotherThreadStillCaptures) {
  Harness h;
  Upstream upstream(echo);
  tcp::socket client = h.newClient();
  const auto tunnel = h.open(client, upstream.port());
  EXPECT_EQ(readExactly(client, kEstablished.size()), kEstablished);
  tunnel->close();
  EXPECT_EQ(readToEnd(client), "");
  ASSERT_NE(h.queue().popWait(milliseconds(2000)), nullptr);
}

TEST(BlindTunnel, CountsByReason) {
  Harness h;
  {
    Upstream upstream(echo);
    tcp::socket client = h.newClient();
    h.open(client, upstream.port(), TunnelReasonTag::kScopedNoCert);
    EXPECT_EQ(readExactly(client, kEstablished.size()), kEstablished);
  }
  {
    Upstream upstream(echo);
    tcp::socket client = h.newClient();
    h.open(client, upstream.port(), TunnelReasonTag::kNonTlsPort);
    EXPECT_EQ(readExactly(client, kEstablished.size()), kEstablished);
  }
  EXPECT_EQ(h.counters().tunnels_scoped_no_cert.load(), 1u);
  EXPECT_EQ(h.counters().tunnels_unscoped.load(), 0u);
}

}  // namespace
}  // namespace llmfw
