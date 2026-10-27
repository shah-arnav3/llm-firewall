#include <gtest/gtest.h>

#include <fstream>
#include <future>
#include <string>
#include <thread>
#include <vector>

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <google/protobuf/io/zero_copy_stream_impl.h>
#include <google/protobuf/util/delimited_message_util.h>
#include <google/protobuf/util/json_util.h>

#include "llmfw/proxy_context.hpp"
#include "llmfw/setup_ca.hpp"
#include "llmfw/setup_leaf.hpp"
#include "net_test_util.hpp"

namespace llmfw {
namespace {

namespace fs = std::filesystem;
using std::chrono::milliseconds;
using test::echo;
using test::kEstablished;
using test::readExactly;
using test::readToEnd;
using test::Upstream;

class TempDir {
 public:
  TempDir() {
    std::string tmpl = (fs::temp_directory_path() / "llmfw-app-XXXXXX").string();
    path_ = ::mkdtemp(tmpl.data());
  }
  ~TempDir() { fs::remove_all(path_); }
  TempDir(const TempDir&) = delete;
  TempDir& operator=(const TempDir&) = delete;
  [[nodiscard]] const fs::path& path() const { return path_; }

 private:
  fs::path path_;
};

ProxyConfig appConfig(const fs::path& log_path, std::uint16_t port) {
  ProxyConfig cfg;
  cfg.listen.port = port;
  cfg.listen.io_threads = 2;
  cfg.decrypt_hosts = {"claude.ai", "*.claude.ai"};
  cfg.clients = {{ClientPathTag::kUi, {"Electron/"}}};
  cfg.metadata_log.path = log_path;
  cfg.metadata_log.logged_header_values = {"user-agent"};
  return cfg;
}

/// Runs a ProxyApp on its own thread; the destructor stops and joins it.
class RunningApp {
 public:
  explicit RunningApp(ProxyConfig cfg) : app_(std::move(cfg)) {
    exit_code_ = std::async(std::launch::async, [this] { return app_.run(); });
  }
  ~RunningApp() {
    if (exit_code_.valid()) {
      app_.requestStop();
      (void)exit_code_.get();
    }
  }
  RunningApp(const RunningApp&) = delete;
  RunningApp& operator=(const RunningApp&) = delete;

  ProxyApp& app() { return app_; }

  /// Requests a stop and returns the exit code, or -1 if run() takes longer than `limit`.
  int stopAndWait(milliseconds limit = milliseconds(5000)) {
    app_.requestStop();
    if (exit_code_.wait_for(limit) != std::future_status::ready) {
      return -1;
    }
    return exit_code_.get();
  }

 private:
  ProxyApp app_;
  std::future<int> exit_code_;
};

/// Connects to the proxy, retrying while it starts up.
bool connectWhenReady(tcp::socket& socket, std::uint16_t port) {
  boost::system::error_code ec;
  for (int attempt = 0; attempt < 200; ++attempt) {
    socket.close(ec);
    socket.connect({asio::ip::make_address("127.0.0.1"), port}, ec);
    if (!ec) {
      return true;
    }
    std::this_thread::sleep_for(milliseconds(10));
  }
  return false;
}

std::vector<llmfw::v1::MetadataRecord> readRecords(const fs::path& path) {
  std::vector<llmfw::v1::MetadataRecord> records;
  std::ifstream in(path);
  for (std::string line; std::getline(in, line);) {
    llmfw::v1::MetadataRecord record;
    EXPECT_TRUE(google::protobuf::util::JsonStringToMessage(line, &record).ok()) << line;
    records.push_back(record);
  }
  return records;
}

TEST(ProxyApp, LogsTunnelsStillOpenAtShutdown) {
  const TempDir tmp;
  const fs::path log = tmp.path() / "logs" / "metadata.jsonl";
  const std::uint16_t port = test::closedPort();
  RunningApp running(appConfig(log, port));
  Upstream upstream(echo);

  asio::io_context io;
  tcp::socket client(io);
  ASSERT_TRUE(connectWhenReady(client, port));
  const std::string head = "CONNECT 127.0.0.1:" + std::to_string(upstream.port()) +
                           " HTTP/1.1\r\nUser-Agent: Claude/2.9 Electron/38\r\n\r\n";
  asio::write(client, asio::buffer(head));
  EXPECT_EQ(readExactly(client, kEstablished.size()), kEstablished);
  asio::write(client, asio::buffer(std::string("hi")));
  EXPECT_EQ(readExactly(client, 2), "hi");

  // The tunnel is still open: shutdown must close it and still log it.
  EXPECT_EQ(running.stopAndWait(), kExitOk);
  EXPECT_EQ(readToEnd(client), "");

  const std::vector<llmfw::v1::MetadataRecord> records = readRecords(log);
  ASSERT_EQ(records.size(), 1u);
  EXPECT_EQ(records[0].kind(), "tunnel");
  EXPECT_EQ(records[0].host(), "127.0.0.1");
  EXPECT_EQ(records[0].request_bytes(), 2u);
  EXPECT_EQ(records[0].response_bytes(), 2u);
  EXPECT_EQ(records[0].client_path(), llmfw::v1::CLIENT_PATH_UI);
  EXPECT_EQ(records[0].user_agent(), "Claude/2.9 Electron/38");
  EXPECT_FALSE(records[0].proxy_instance_id().empty());
}

TEST(ProxyApp, ServesThePacForTheBoundPort) {
  const TempDir tmp;
  const std::uint16_t port = test::closedPort();
  RunningApp running(appConfig(tmp.path() / "metadata.jsonl", port));
  asio::io_context io;
  tcp::socket client(io);
  ASSERT_TRUE(connectWhenReady(client, port));
  asio::write(client, asio::buffer(std::string("GET /proxy.pac HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")));
  const std::string response = readToEnd(client);
  EXPECT_TRUE(response.starts_with("HTTP/1.1 200 OK\r\n")) << response.substr(0, 80);
  EXPECT_NE(response.find("return \"PROXY 127.0.0.1:" + std::to_string(port) + "; DIRECT\";"), std::string::npos);
  EXPECT_EQ(response.find("{{"), std::string::npos);
  EXPECT_EQ(running.stopAndWait(), kExitOk);
}

TEST(ProxyApp, StopRequestedBeforeRunReturnsPromptly) {
  const TempDir tmp;
  ProxyApp app(appConfig(tmp.path() / "metadata.jsonl", test::closedPort()));
  app.requestStop();
  const auto start = Clock::now();
  EXPECT_EQ(app.run(), kExitOk);
  EXPECT_LT(Clock::now() - start, milliseconds(3000));
}

TEST(ProxyApp, ReturnsBindErrorWhenPortIsTaken) {
  const TempDir tmp;
  asio::io_context io;
  tcp::acceptor taken(io, {asio::ip::make_address("127.0.0.1"), 0});
  ProxyApp app(appConfig(tmp.path() / "metadata.jsonl", taken.local_endpoint().port()));
  EXPECT_EQ(app.run(), kExitBind);
}

TEST(ProxyApp, ReturnsSinkErrorWhenLogCannotBeOpened) {
  ProxyApp app(appConfig("/dev/null/llm-firewall/metadata.jsonl", test::closedPort()));
  EXPECT_EQ(app.run(), kExitSink);
}

/// A listening collector socket in a private directory under /tmp (short enough for sun_path).
class CollectorSocket {
 public:
  CollectorSocket() {
    std::string tmpl = "/tmp/llmfw-col-XXXXXX";
    dir_ = ::mkdtemp(tmpl.data());
    listener_ = ::socket(AF_UNIX, SOCK_STREAM, 0);
    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    (dir_ / "c.sock").string().copy(addr.sun_path, sizeof(addr.sun_path) - 1);
    EXPECT_EQ(::bind(listener_, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)), 0);
    EXPECT_EQ(::listen(listener_, 4), 0);
  }
  ~CollectorSocket() {
    ::close(listener_);
    fs::remove_all(dir_);
  }
  CollectorSocket(const CollectorSocket&) = delete;
  CollectorSocket& operator=(const CollectorSocket&) = delete;

  void pointAt(ProxyConfig& cfg) const {
    cfg.mode = CaptureMode::kFull;
    cfg.ipc.socket_dir = dir_;
    cfg.ipc.socket_name = "c.sock";
  }

  /// Accepts the proxy's connection and reads frames until it closes.
  std::vector<llmfw::v1::Frame> readAll() {
    std::vector<llmfw::v1::Frame> frames;
    const int conn = ::accept(listener_, nullptr, nullptr);
    EXPECT_GE(conn, 0);
    timeval timeout{.tv_sec = 2, .tv_usec = 0};
    ::setsockopt(conn, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    {
      google::protobuf::io::FileInputStream input(conn);
      llmfw::v1::Frame frame;
      while (google::protobuf::util::ParseDelimitedFromZeroCopyStream(&frame, &input, nullptr)) {
        frames.push_back(frame);
      }
    }
    ::close(conn);
    return frames;
  }

 private:
  fs::path dir_;
  int listener_ = -1;
};

TEST(ProxyApp, FullModeSendsCapturesToTheCollector) {
  const TempDir tmp;
  const fs::path log = tmp.path() / "metadata.jsonl";
  const std::uint16_t port = test::closedPort();
  CollectorSocket collector;
  ProxyConfig cfg = appConfig(log, port);
  collector.pointAt(cfg);
  RunningApp running(std::move(cfg));
  Upstream upstream(echo);

  asio::io_context io;
  tcp::socket client(io);
  ASSERT_TRUE(connectWhenReady(client, port));
  asio::write(client, asio::buffer("CONNECT 127.0.0.1:" + std::to_string(upstream.port()) + " HTTP/1.1\r\n\r\n"));
  EXPECT_EQ(readExactly(client, kEstablished.size()), kEstablished);
  asio::write(client, asio::buffer(std::string("hi")));
  EXPECT_EQ(readExactly(client, 2), "hi");
  EXPECT_EQ(running.stopAndWait(), kExitOk);

  const std::vector<llmfw::v1::Frame> frames = collector.readAll();
  ASSERT_GE(frames.size(), 3u);
  EXPECT_TRUE(frames[0].has_hello());
  EXPECT_FALSE(frames[0].hello().proxy_version().empty());
  EXPECT_TRUE(frames[1].has_stats());
  const llmfw::v1::Frame& capture = frames.back();
  ASSERT_TRUE(capture.has_capture());
  EXPECT_EQ(capture.capture().tunnel().bytes_client_to_server(), 2u);
  EXPECT_FALSE(fs::exists(log)) << "full mode writes no metadata log";
}

TEST(ProxyApp, FullModeRunsWithoutACollector) {
  const TempDir tmp;
  const std::uint16_t port = test::closedPort();
  ProxyConfig cfg = appConfig(tmp.path() / "metadata.jsonl", port);
  cfg.mode = CaptureMode::kFull;
  cfg.ipc.socket_dir = tmp.path() / "missing";
  RunningApp running(std::move(cfg));
  asio::io_context io;
  tcp::socket client(io);
  EXPECT_TRUE(connectWhenReady(client, port)) << "the proxy serves even with captures going nowhere";
  client.close();
  EXPECT_EQ(running.stopAndWait(), kExitOk);
}

/// Writes a CA-issued leaf into a fresh private directory under `tmp` and points cfg.certs at it.
void writeCerts(const TempDir& tmp, ProxyConfig& cfg) {
  const fs::path dir = tmp.path() / "certs";
  fs::create_directory(dir);
  fs::permissions(dir, fs::perms::owner_all, fs::perm_options::replace);
  setup::CaSpec spec;
  spec.common_name = "llm-firewall local CA (app test)";
  const setup::EphemeralCa ca = setup::generateConstrainedCa(spec);
  setup::writeLeaf(setup::issueLeaf(ca, setup::LeafSpec{}), dir / "leaf.pem", dir / "leaf.key");
  cfg.certs.dir = dir;
}

TEST(ProxyApp, ReturnsCertErrorWhenDecryptIsOnWithoutCertificates) {
  const TempDir tmp;
  ProxyConfig cfg = appConfig(tmp.path() / "metadata.jsonl", test::closedPort());
  cfg.decrypt = true;
  cfg.certs.dir = tmp.path() / "no-certs";
  EXPECT_EQ(ProxyApp(std::move(cfg)).run(), kExitCerts);
  EXPECT_FALSE(fs::exists(tmp.path() / "metadata.jsonl")) << "nothing else starts";
}

TEST(ProxyApp, ReturnsConfigErrorForAnUnreadableTrustBundle) {
  const TempDir tmp;
  ProxyConfig cfg = appConfig(tmp.path() / "metadata.jsonl", test::closedPort());
  writeCerts(tmp, cfg);
  cfg.decrypt = true;
  cfg.upstream.trust = UpstreamTrustMode::kPemBundle;
  cfg.upstream.pem_bundle = tmp.path() / "missing.pem";
  EXPECT_EQ(ProxyApp(std::move(cfg)).run(), kExitConfig);
}

TEST(ProxyApp, StartsAndServesWithDecryptOn) {
  const TempDir tmp;
  const std::uint16_t port = test::closedPort();
  ProxyConfig cfg = appConfig(tmp.path() / "metadata.jsonl", port);
  writeCerts(tmp, cfg);
  cfg.decrypt = true;
  RunningApp running(std::move(cfg));
  asio::io_context io;
  tcp::socket client(io);
  ASSERT_TRUE(connectWhenReady(client, port));
  asio::write(client, asio::buffer(std::string("GET /proxy.pac HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")));
  EXPECT_TRUE(readToEnd(client).starts_with("HTTP/1.1 200 OK\r\n"));
  EXPECT_EQ(running.stopAndWait(), kExitOk);
}

}  // namespace
}  // namespace llmfw
