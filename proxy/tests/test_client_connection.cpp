#include <gtest/gtest.h>

#include <string>
#include <thread>
#include <vector>

#include <boost/asio/executor_work_guard.hpp>

#include "llmfw/connect_handler.hpp"
#include "llmfw/listener.hpp"
#include "net_test_util.hpp"

namespace llmfw {
namespace {

using std::chrono::milliseconds;
using test::echo;
using test::kEstablished;
using test::readExactly;
using test::readToEnd;
using test::Upstream;

const std::string kUserAgent = "Mozilla/5.0 Claude/2.9 Electron/38";
const std::string kTestPac = "function FindProxyForURL(url, host) { return \"DIRECT\"; }\n";

/// A listener on a free loopback port, served by two I/O threads.
class ProxyHarness {
 public:
  explicit ProxyHarness(std::vector<std::string> scope_patterns = {}, milliseconds idle = milliseconds(5000))
      : scope_(std::move(scope_patterns)) {
    config_.listen.port = 0;
    config_.listen.idle_timeout = idle;
    listener_ = std::make_unique<Listener>(io_, config_.listen, context_);
    listener_->start();
    for (int i = 0; i < 2; ++i) {
      threads_.emplace_back([this] { io_.run(); });
    }
  }
  ~ProxyHarness() {
    listener_->stop();
    work_.reset();
    io_.stop();
    for (std::thread& t : threads_) {
      t.join();
    }
  }
  ProxyHarness(const ProxyHarness&) = delete;
  ProxyHarness& operator=(const ProxyHarness&) = delete;

  /// A blocking client socket connected to the proxy.
  tcp::socket connect() {
    tcp::socket socket(client_io_);
    socket.connect(listener_->localEndpoint());
    return socket;
  }

  Listener& listener() { return *listener_; }
  CaptureQueue& queue() { return queue_; }
  ProxyCounters& counters() { return counters_; }

 private:
  ProxyConfig config_;
  HostScope scope_;
  ProxyCounters counters_;
  CaptureQueue queue_{100, 1 << 20, counters_};
  ClientClassifier classifier_{{{ClientPathTag::kUi, {"Electron/"}}}};
  CaptureBuildContext build_{classifier_, counters_};
  TunnelRegistry tunnels_;
  std::string pac_ = kTestPac;
  ProxyContext context_{config_, scope_, queue_, counters_, build_, tunnels_, pac_};
  asio::io_context io_;
  asio::executor_work_guard<asio::io_context::executor_type> work_ = asio::make_work_guard(io_);
  std::unique_ptr<Listener> listener_;
  std::vector<std::thread> threads_;
  asio::io_context client_io_;
};

std::string connectHead(const std::string& authority) {
  return "CONNECT " + authority + " HTTP/1.1\r\nHost: " + authority + "\r\nUser-Agent: " + kUserAgent + "\r\n\r\n";
}

TEST(ClientConnection, TunnelsConnectToUpstream) {
  ProxyHarness proxy;
  Upstream upstream(echo);
  tcp::socket client = proxy.connect();
  asio::write(client, asio::buffer(connectHead("127.0.0.1:" + std::to_string(upstream.port())) + "early"));

  EXPECT_EQ(readExactly(client, kEstablished.size()), kEstablished);
  EXPECT_EQ(readExactly(client, 5), "early") << "bytes after the head must reach the upstream";
  client.shutdown(tcp::socket::shutdown_send);
  EXPECT_EQ(readToEnd(client), "");

  const auto frame = proxy.queue().popWait(milliseconds(2000));
  ASSERT_NE(frame, nullptr);
  const llmfw::v1::Capture& capture = frame->capture();
  EXPECT_EQ(capture.connection_id(), 1u);
  EXPECT_EQ(capture.client().connect_user_agent(), kUserAgent);
  EXPECT_EQ(capture.client().path(), llmfw::v1::CLIENT_PATH_UI);
  EXPECT_EQ(capture.tunnel().host(), "127.0.0.1");
  EXPECT_EQ(capture.tunnel().reason(), llmfw::v1::TUNNEL_REASON_UNSCOPED_HOST);
  EXPECT_EQ(capture.tunnel().bytes_client_to_server(), 5u);
  EXPECT_EQ(proxy.counters().connections_accepted.load(), 1u);
}

TEST(ClientConnection, AcceptsHeadSplitAcrossWrites) {
  ProxyHarness proxy;
  Upstream upstream(echo);
  tcp::socket client = proxy.connect();
  const std::string head = connectHead("127.0.0.1:" + std::to_string(upstream.port()));
  for (std::size_t at = 0; at < head.size(); at += 7) {
    asio::write(client, asio::buffer(head.substr(at, 7)));
    std::this_thread::sleep_for(milliseconds(2));
  }
  EXPECT_EQ(readExactly(client, kEstablished.size()), kEstablished);
}

TEST(ClientConnection, ScopedHostIsTunneledWithItsReason) {
  ProxyHarness proxy({"localhost"});
  Upstream upstream(echo);
  tcp::socket client = proxy.connect();
  asio::write(client, asio::buffer(connectHead("LocalHost:" + std::to_string(upstream.port()))));
  EXPECT_EQ(readExactly(client, kEstablished.size()), kEstablished);
  client.close();

  const auto frame = proxy.queue().popWait(milliseconds(2000));
  ASSERT_NE(frame, nullptr);
  EXPECT_EQ(frame->capture().tunnel().host(), "localhost") << "the normalized host is recorded";
  EXPECT_EQ(frame->capture().tunnel().reason(), llmfw::v1::TUNNEL_REASON_NON_TLS_PORT);
}

TEST(ClientConnection, RejectsNonConnectWith405) {
  ProxyHarness proxy;
  tcp::socket client = proxy.connect();
  asio::write(client, asio::buffer(std::string("GET http://claude.ai/ HTTP/1.1\r\nHost: claude.ai\r\n\r\n")));
  EXPECT_EQ(readToEnd(client),
            "HTTP/1.1 405 Method Not Allowed\r\nAllow: CONNECT\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
  EXPECT_EQ(proxy.counters().non_connect_requests_rejected.load(), 1u);
  EXPECT_EQ(proxy.queue().popWait(milliseconds(200)), nullptr);
}

TEST(ClientConnection, ServesThePacOnGet) {
  ProxyHarness proxy;
  tcp::socket client = proxy.connect();
  asio::write(client, asio::buffer(std::string("GET /proxy.pac HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")));
  EXPECT_EQ(readToEnd(client), "HTTP/1.1 200 OK\r\nContent-Type: application/x-ns-proxy-autoconfig\r\nContent-Length: " +
                                   std::to_string(kTestPac.size()) +
                                   "\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n" + kTestPac);
  EXPECT_EQ(proxy.counters().non_connect_requests_rejected.load(), 0u);
  EXPECT_EQ(proxy.queue().popWait(milliseconds(200)), nullptr) << "serving the PAC is not a capture";
}

TEST(ClientConnection, ServesThePacOnlyForGetOnItsPath) {
  ProxyHarness proxy;
  for (const char* head : {"GET /proxy.pac.bak HTTP/1.1\r\n\r\n", "GET /proxy.pac?x=1 HTTP/1.1\r\n\r\n",
                           "POST /proxy.pac HTTP/1.1\r\nContent-Length: 0\r\n\r\n",
                           "GET http://127.0.0.1/proxy.pac HTTP/1.1\r\n\r\n"}) {
    tcp::socket client = proxy.connect();
    asio::write(client, asio::buffer(std::string(head)));
    EXPECT_TRUE(readToEnd(client).starts_with("HTTP/1.1 405 Method Not Allowed")) << head;
  }
  EXPECT_EQ(proxy.counters().non_connect_requests_rejected.load(), 4u);
}

TEST(ClientConnection, RejectsMalformedHeadWith400) {
  ProxyHarness proxy;
  tcp::socket client = proxy.connect();
  asio::write(client, asio::buffer(std::string("CONNECT claude.ai HTTP/1.1\r\n\r\n")));
  EXPECT_EQ(readToEnd(client), "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
}

TEST(ClientConnection, RejectsOversizeHeadWith400) {
  ProxyHarness proxy;
  tcp::socket client = proxy.connect();
  const std::string start = "CONNECT claude.ai:443 HTTP/1.1\r\nX-Pad: ";
  boost::system::error_code ec;
  asio::write(client, asio::buffer(start + std::string(kMaxProxyRequestHeadBytes, 'a')), ec);
  EXPECT_TRUE(readToEnd(client).starts_with("HTTP/1.1 400 Bad Request"));
}

TEST(ClientConnection, ClosesWhenHeadNeverCompletes) {
  ProxyHarness proxy({}, milliseconds(200));
  tcp::socket client = proxy.connect();
  asio::write(client, asio::buffer(std::string("CONNECT claude.ai:443 HTTP/1.1\r\n")));
  const auto start = Clock::now();
  EXPECT_EQ(readToEnd(client), "");
  EXPECT_LT(Clock::now() - start, milliseconds(3000));
}

TEST(ClientConnection, ClientClosingBeforeHeadCapturesNothing) {
  ProxyHarness proxy;
  {
    tcp::socket client = proxy.connect();
    asio::write(client, asio::buffer(std::string("CONNECT 127.0.0.1:")));
  }
  EXPECT_EQ(proxy.queue().popWait(milliseconds(300)), nullptr);
  EXPECT_EQ(proxy.counters().connections_accepted.load(), 1u);
}

TEST(Listener, AssignsIncreasingConnectionIds) {
  ProxyHarness proxy;
  for (std::uint64_t expected = 1; expected <= 3; ++expected) {
    Upstream upstream(echo);
    tcp::socket client = proxy.connect();
    asio::write(client, asio::buffer(connectHead("127.0.0.1:" + std::to_string(upstream.port()))));
    EXPECT_EQ(readExactly(client, kEstablished.size()), kEstablished);
    client.close();
    const auto frame = proxy.queue().popWait(milliseconds(2000));
    ASSERT_NE(frame, nullptr);
    EXPECT_EQ(frame->capture().connection_id(), expected);
  }
}

TEST(Listener, RejectsNonLoopbackAddress) {
  asio::io_context io;
  ProxyConfig config;
  HostScope scope({});
  ProxyCounters counters;
  CaptureQueue queue(10, 1 << 20, counters);
  ClientClassifier classifier({});
  CaptureBuildContext build{classifier, counters};
  TunnelRegistry tunnels;
  const std::string pac;
  ProxyContext context{config, scope, queue, counters, build, tunnels, pac};
  for (const char* address : {"0.0.0.0", "192.168.1.10", "localhost"}) {
    ListenConfig listen;
    listen.address = address;
    listen.port = 0;
    EXPECT_THROW(Listener(io, listen, context), ConfigError) << address;
  }
}

TEST(Listener, StopRefusesNewConnections) {
  ProxyHarness proxy;
  const tcp::endpoint endpoint = proxy.listener().localEndpoint();
  proxy.listener().stop();
  asio::io_context io;
  tcp::socket client(io);
  boost::system::error_code ec;
  for (int attempt = 0; attempt < 50; ++attempt) {  // stop() is asynchronous.
    client.close(ec);
    client.connect(endpoint, ec);
    if (ec) {
      break;
    }
    std::this_thread::sleep_for(milliseconds(10));
  }
  EXPECT_TRUE(ec) << "connections still accepted after stop()";
}

}  // namespace
}  // namespace llmfw
