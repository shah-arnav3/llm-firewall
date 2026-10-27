#include <gtest/gtest.h>

#include <chrono>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <google/protobuf/io/zero_copy_stream_impl.h>
#include <google/protobuf/util/delimited_message_util.h>

#include "llmfw/unix_socket_writer.hpp"

namespace llmfw {
namespace {

namespace fs = std::filesystem;
using std::chrono::milliseconds;
using SteadyClock = std::chrono::steady_clock;

/// The collector's side: a private directory under /tmp (short enough for sun_path)
/// that can hold a listening socket, and the frames read from one accepted connection.
class FakeCollector {
 public:
  FakeCollector() {
    std::string tmpl = "/tmp/llmfw-ipc-XXXXXX";
    dir_ = ::mkdtemp(tmpl.data());
    cfg.socket_dir = dir_;
    cfg.socket_name = "c.sock";
    cfg.reconnect_backoff_initial = milliseconds(250);
    cfg.reconnect_backoff_max = milliseconds(1000);
    cfg.stats_interval = milliseconds(30'000);
  }
  ~FakeCollector() {
    closeAll();
    fs::remove_all(dir_);
  }
  FakeCollector(const FakeCollector&) = delete;
  FakeCollector& operator=(const FakeCollector&) = delete;

  void listen() {
    listener_ = ::socket(AF_UNIX, SOCK_STREAM, 0);
    ASSERT_GE(listener_, 0);
    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    cfg.socketPath().string().copy(addr.sun_path, sizeof(addr.sun_path) - 1);
    ASSERT_EQ(::bind(listener_, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)), 0);
    ASSERT_EQ(::listen(listener_, 4), 0);
  }

  /// Accepts the writer's pending connection (connect() completes before this).
  void accept() {
    conn_ = ::accept(listener_, nullptr, nullptr);
    ASSERT_GE(conn_, 0);
    timeval timeout{.tv_sec = 2, .tv_usec = 0};
    ::setsockopt(conn_, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    input_ = std::make_unique<google::protobuf::io::FileInputStream>(conn_);
  }

  /// The next frame, or nullopt at end of stream or after 2 s without one.
  std::optional<llmfw::v1::Frame> next() {
    llmfw::v1::Frame frame;
    bool clean_eof = false;
    if (!google::protobuf::util::ParseDelimitedFromZeroCopyStream(&frame, input_.get(), &clean_eof)) {
      return std::nullopt;
    }
    return frame;
  }

  void closeConnection() {
    input_.reset();
    if (conn_ >= 0) {
      ::close(conn_);
      conn_ = -1;
    }
  }

  [[nodiscard]] const fs::path& dir() const { return dir_; }

  IpcConfig cfg;

 private:
  void closeAll() {
    closeConnection();
    if (listener_ >= 0) {
      ::close(listener_);
    }
  }

  fs::path dir_;
  int listener_ = -1;
  int conn_ = -1;
  std::unique_ptr<google::protobuf::io::FileInputStream> input_;
};

llmfw::v1::Frame captureFrame(std::uint64_t id, std::size_t payload_bytes = 0) {
  llmfw::v1::Frame frame;
  frame.mutable_capture()->set_capture_id(id);
  frame.mutable_capture()->mutable_websocket()->set_payload(std::string(payload_bytes, 'p'));
  return frame;
}

struct WriterFixture {
  explicit WriterFixture(FakeCollector& collector, milliseconds send_timeout = UnixSocketWriter::kDefaultSendTimeout)
      : writer(collector.cfg, "instance-1", "0.1.0", 1'790'000'000'000, counters, send_timeout) {}

  ProxyCounters counters;
  UnixSocketWriter writer;
  SteadyClock::time_point t0 = SteadyClock::now();
};

TEST(UnixSocketWriter, SendsHelloThenStatsOnConnect) {
  FakeCollector collector;
  collector.listen();
  WriterFixture f(collector);
  f.counters.connections_accepted = 4;
  EXPECT_FALSE(f.writer.connected()) << "connecting waits for the first tick";
  f.writer.tick(f.t0);
  ASSERT_TRUE(f.writer.connected());

  collector.accept();
  const auto hello = collector.next();
  ASSERT_TRUE(hello && hello->has_hello());
  EXPECT_EQ(hello->hello().protocol_version(), 1u);
  EXPECT_EQ(hello->hello().proxy_instance_id(), "instance-1");
  EXPECT_EQ(hello->hello().proxy_version(), "0.1.0");
  EXPECT_EQ(hello->hello().started_unix_ms(), 1'790'000'000'000);
  const auto stats = collector.next();
  ASSERT_TRUE(stats && stats->has_stats());
  EXPECT_EQ(stats->stats().connections_accepted(), 4u);
}

TEST(UnixSocketWriter, WritesFramesInOrder) {
  FakeCollector collector;
  collector.listen();
  WriterFixture f(collector);
  f.writer.tick(f.t0);
  for (std::uint64_t id = 1; id <= 3; ++id) {
    EXPECT_TRUE(f.writer.write(captureFrame(id, id * 1000)));
  }
  collector.accept();
  ASSERT_TRUE(collector.next()->has_hello());
  ASSERT_TRUE(collector.next()->has_stats());
  for (std::uint64_t id = 1; id <= 3; ++id) {
    const auto frame = collector.next();
    ASSERT_TRUE(frame && frame->has_capture());
    EXPECT_EQ(frame->capture().capture_id(), id);
    EXPECT_EQ(frame->capture().websocket().payload().size(), id * 1000);
  }
}

TEST(UnixSocketWriter, RefusesAFrameOverTheLimitAndStaysConnected) {
  FakeCollector collector;
  collector.cfg.max_frame_bytes = 100;
  collector.listen();
  WriterFixture f(collector);
  f.writer.tick(f.t0);
  EXPECT_FALSE(f.writer.write(captureFrame(1, 200)));
  EXPECT_TRUE(f.writer.connected());
  EXPECT_TRUE(f.writer.write(captureFrame(2)));
}

TEST(UnixSocketWriter, WriteReturnsFalseWhenNoCollectorListens) {
  FakeCollector collector;
  WriterFixture f(collector);
  f.writer.tick(f.t0);
  EXPECT_FALSE(f.writer.connected());
  EXPECT_FALSE(f.writer.write(captureFrame(1)));
}

TEST(UnixSocketWriter, RefusesADirectoryThatIsNotPrivate) {
  FakeCollector collector;
  collector.listen();
  ASSERT_EQ(::chmod(collector.dir().c_str(), 0755), 0);
  WriterFixture f(collector);
  f.writer.tick(f.t0);
  EXPECT_FALSE(f.writer.connected());
}

TEST(UnixSocketWriter, RefusesASocketPathThatIsNotASocket) {
  FakeCollector collector;
  std::fclose(std::fopen(collector.cfg.socketPath().c_str(), "w"));
  WriterFixture f(collector);
  f.writer.tick(f.t0);
  EXPECT_FALSE(f.writer.connected());
}

TEST(UnixSocketWriter, ReconnectsWithExponentialBackoff) {
  FakeCollector collector;
  WriterFixture f(collector);
  f.writer.tick(f.t0);  // Fails; the next attempt is 250 ms later.
  f.writer.tick(f.t0 + milliseconds(250));  // Fails; the next is 500 ms after that.
  collector.listen();
  f.writer.tick(f.t0 + milliseconds(749));
  EXPECT_FALSE(f.writer.connected()) << "still backing off";
  f.writer.tick(f.t0 + milliseconds(750));
  EXPECT_TRUE(f.writer.connected());
}

TEST(UnixSocketWriter, TheBackoffStopsGrowingAtItsMaximum) {
  FakeCollector collector;
  WriterFixture f(collector);
  SteadyClock::time_point t = f.t0;
  for (const int wait : {250, 500, 1000, 1000}) {
    f.writer.tick(t);
    t += milliseconds(wait);
  }
  collector.listen();
  f.writer.tick(t - milliseconds(1));
  EXPECT_FALSE(f.writer.connected());
  f.writer.tick(t);
  EXPECT_TRUE(f.writer.connected());
}

TEST(UnixSocketWriter, APeerCloseFailsTheWriteWithoutSigpipe) {
  FakeCollector collector;
  collector.listen();
  WriterFixture f(collector);
  f.writer.tick(f.t0);
  collector.accept();
  collector.closeConnection();
  bool failed = false;
  for (int i = 0; i < 100 && !failed; ++i) {
    failed = !f.writer.write(captureFrame(1, 1000));
  }
  EXPECT_TRUE(failed);
  EXPECT_FALSE(f.writer.connected());
}

TEST(UnixSocketWriter, AStalledCollectorTimesTheWriteOut) {
  FakeCollector collector;
  collector.listen();
  WriterFixture f(collector, milliseconds(100));
  f.writer.tick(f.t0);
  // Never accepted or read, so the socket buffers fill and the send blocks.
  const auto start = SteadyClock::now();
  EXPECT_FALSE(f.writer.write(captureFrame(1, 4 << 20)));
  EXPECT_LT(SteadyClock::now() - start, std::chrono::seconds(2));
  EXPECT_FALSE(f.writer.connected());
}

TEST(UnixSocketWriter, SendsStatsEveryInterval) {
  FakeCollector collector;
  collector.listen();
  WriterFixture f(collector);
  f.writer.tick(f.t0);
  f.counters.http_parse_errors = 2;
  f.writer.tick(f.t0 + milliseconds(29'999));
  f.writer.tick(f.t0 + milliseconds(30'000));
  EXPECT_TRUE(f.writer.write(captureFrame(9)));
  collector.accept();
  ASSERT_TRUE(collector.next()->has_hello());
  ASSERT_EQ(collector.next()->stats().http_parse_errors(), 0u);
  const auto stats = collector.next();
  ASSERT_TRUE(stats && stats->has_stats()) << "one more stats frame, at 30 s";
  EXPECT_EQ(stats->stats().http_parse_errors(), 2u);
  const auto capture = collector.next();
  ASSERT_TRUE(capture && capture->has_capture());
}

TEST(UnixSocketWriter, CloseDisconnects) {
  FakeCollector collector;
  collector.listen();
  WriterFixture f(collector);
  f.writer.tick(f.t0);
  ASSERT_TRUE(f.writer.connected());
  f.writer.close();
  EXPECT_FALSE(f.writer.connected());
  collector.accept();
  ASSERT_TRUE(collector.next()->has_hello());
  ASSERT_TRUE(collector.next()->has_stats());
  EXPECT_FALSE(collector.next()) << "end of stream";
}

}  // namespace
}  // namespace llmfw
