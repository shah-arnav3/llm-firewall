#include <gtest/gtest.h>

#include <fstream>
#include <future>
#include <string>
#include <thread>
#include <vector>

#include <google/protobuf/util/json_util.h>

#include "llmfw/proxy_context.hpp"
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

TEST(ProxyApp, RejectsFullMode) {
  const TempDir tmp;
  ProxyConfig cfg = appConfig(tmp.path() / "metadata.jsonl", test::closedPort());
  cfg.mode = CaptureMode::kFull;
  EXPECT_EQ(ProxyApp(std::move(cfg)).run(), kExitConfig);
}

}  // namespace
}  // namespace llmfw
