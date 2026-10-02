#include <gtest/gtest.h>

#include <fstream>
#include <string>
#include <vector>

#include <sys/stat.h>
#include <unistd.h>

#include <google/protobuf/util/json_util.h>

#include "llmfw/metadata_logger.hpp"

namespace llmfw {
namespace {

namespace fs = std::filesystem;

/// A fresh temp directory, removed with everything in it when the object goes away.
class TempDir {
 public:
  TempDir() {
    std::string tmpl = (fs::temp_directory_path() / "llmfw-log-XXXXXX").string();
    path_ = ::mkdtemp(tmpl.data());
  }
  ~TempDir() { fs::remove_all(path_); }
  TempDir(const TempDir&) = delete;
  TempDir& operator=(const TempDir&) = delete;
  [[nodiscard]] const fs::path& path() const { return path_; }

 private:
  fs::path path_;
};

llmfw::v1::Capture tunnelCapture(std::uint64_t id) {
  llmfw::v1::Capture capture;
  capture.set_capture_id(id);
  capture.set_connection_id(7);
  capture.mutable_client()->set_path(llmfw::v1::CLIENT_PATH_UI);
  capture.mutable_client()->set_user_agent("Claude/2.9 Electron/38");
  capture.mutable_timings()->set_start_unix_us(1'790'000'000'000'000);
  llmfw::v1::TunnelSummary& tunnel = *capture.mutable_tunnel();
  tunnel.set_host("claude.ai");
  tunnel.set_port(443);
  tunnel.set_reason(llmfw::v1::TUNNEL_REASON_SCOPED_NO_CERT);
  tunnel.set_bytes_client_to_server(100);
  tunnel.set_bytes_server_to_client(2000);
  tunnel.set_duration_us(5'000'000);
  return capture;
}

llmfw::v1::Frame frameOf(const llmfw::v1::Capture& capture) {
  llmfw::v1::Frame frame;
  *frame.mutable_capture() = capture;
  return frame;
}

MetadataLogConfig logConfig(const fs::path& path) {
  MetadataLogConfig cfg;
  cfg.path = path;
  cfg.logged_header_values = {"content-type", "user-agent"};
  return cfg;
}

std::vector<std::string> readLines(const fs::path& path) {
  std::ifstream in(path);
  std::vector<std::string> lines;
  for (std::string line; std::getline(in, line);) {
    lines.push_back(line);
  }
  return lines;
}

mode_t modeOf(const fs::path& path) {
  struct stat st {};
  EXPECT_EQ(::stat(path.c_str(), &st), 0) << path;
  return st.st_mode & 0777;
}

TEST(ToMetadataRecord, MapsTunnelFields) {
  const llmfw::v1::MetadataRecord record = toMetadataRecord(tunnelCapture(3), logConfig("unused"), "inst");
  EXPECT_EQ(record.proxy_instance_id(), "inst");
  EXPECT_EQ(record.capture_id(), 3u);
  EXPECT_EQ(record.connection_id(), 7u);
  EXPECT_EQ(record.kind(), "tunnel");
  EXPECT_EQ(record.client_path(), llmfw::v1::CLIENT_PATH_UI);
  EXPECT_EQ(record.user_agent(), "Claude/2.9 Electron/38");
  EXPECT_EQ(record.host(), "claude.ai");
  EXPECT_EQ(record.tunnel_reason(), llmfw::v1::TUNNEL_REASON_SCOPED_NO_CERT);
  EXPECT_EQ(record.request_bytes(), 100u);
  EXPECT_EQ(record.response_bytes(), 2000u);
  EXPECT_EQ(record.tunnel_duration_us(), 5'000'000u);
  EXPECT_EQ(record.timings().start_unix_us(), 1'790'000'000'000'000);
}

TEST(ToMetadataRecord, KeepsUserAgentOnlyWhenAllowlisted) {
  MetadataLogConfig cfg = logConfig("unused");
  cfg.logged_header_values = {"content-type"};
  EXPECT_TRUE(toMetadataRecord(tunnelCapture(1), cfg, "inst").user_agent().empty());
}

TEST(ToMetadataRecord, MapsKindForEveryPayload) {
  const MetadataLogConfig cfg = logConfig("unused");
  llmfw::v1::Capture http;
  http.mutable_http();
  llmfw::v1::Capture websocket;
  websocket.mutable_websocket();
  EXPECT_EQ(toMetadataRecord(http, cfg, "i").kind(), "http");
  EXPECT_EQ(toMetadataRecord(websocket, cfg, "i").kind(), "websocket");
  EXPECT_EQ(toMetadataRecord(llmfw::v1::Capture{}, cfg, "i").kind(), "");
}

TEST(ToMetadataRecord, NeverCopiesBodyOrHeaderValues) {
  llmfw::v1::Capture capture;
  llmfw::v1::HttpRequest& request = *capture.mutable_http()->mutable_request();
  request.mutable_body()->set_data("SECRET-BODY");
  llmfw::v1::Header& header = *request.add_headers();
  header.set_name("authorization");
  header.set_value("SECRET-HEADER");
  const std::string serialized = toMetadataRecord(capture, logConfig("unused"), "i").SerializeAsString();
  EXPECT_EQ(serialized.find("SECRET"), std::string::npos);
}

TEST(MetadataLogger, CreatesPrivateDirectoriesAndFile) {
  const TempDir tmp;
  const fs::path path = tmp.path() / "a" / "b" / "metadata.jsonl";
  MetadataLogger logger(logConfig(path), "inst");
  EXPECT_EQ(modeOf(tmp.path() / "a"), 0700u);
  EXPECT_EQ(modeOf(tmp.path() / "a" / "b"), 0700u);
  EXPECT_EQ(modeOf(path), 0600u);
}

TEST(MetadataLogger, LeavesExistingDirectoryModesAlone) {
  const TempDir tmp;
  ASSERT_EQ(::chmod(tmp.path().c_str(), 0755), 0);
  MetadataLogger logger(logConfig(tmp.path() / "metadata.jsonl"), "inst");
  EXPECT_EQ(modeOf(tmp.path()), 0755u);
}

TEST(MetadataLogger, TightensExistingFileTo0600) {
  const TempDir tmp;
  const fs::path path = tmp.path() / "metadata.jsonl";
  std::ofstream(path) << "";
  ASSERT_EQ(::chmod(path.c_str(), 0644), 0);
  MetadataLogger logger(logConfig(path), "inst");
  EXPECT_EQ(modeOf(path), 0600u);
}

TEST(MetadataLogger, WritesOneJsonObjectPerLine) {
  const TempDir tmp;
  const fs::path path = tmp.path() / "metadata.jsonl";
  {
    MetadataLogger logger(logConfig(path), "inst");
    for (std::uint64_t id = 1; id <= 3; ++id) {
      ASSERT_TRUE(logger.write(frameOf(tunnelCapture(id))));
    }
  }
  const std::vector<std::string> lines = readLines(path);
  ASSERT_EQ(lines.size(), 3u);
  for (std::size_t i = 0; i < lines.size(); ++i) {
    EXPECT_NE(lines[i].find("\"capture_id\":"), std::string::npos) << "expected proto field names: " << lines[i];
    llmfw::v1::MetadataRecord record;
    ASSERT_TRUE(google::protobuf::util::JsonStringToMessage(lines[i], &record).ok()) << lines[i];
    EXPECT_EQ(record.capture_id(), i + 1);
    EXPECT_EQ(record.host(), "claude.ai");
  }
}

TEST(MetadataLogger, SkipsNonCaptureFrames) {
  const TempDir tmp;
  const fs::path path = tmp.path() / "metadata.jsonl";
  MetadataLogger logger(logConfig(path), "inst");
  llmfw::v1::Frame stats;
  stats.mutable_stats()->set_connections_accepted(1);
  EXPECT_TRUE(logger.write(stats));
  EXPECT_EQ(fs::file_size(path), 0u);
}

TEST(MetadataLogger, AppendsToExistingFile) {
  const TempDir tmp;
  const fs::path path = tmp.path() / "metadata.jsonl";
  std::ofstream(path) << "{\"earlier\":true}\n";
  {
    MetadataLogger logger(logConfig(path), "inst");
    ASSERT_TRUE(logger.write(frameOf(tunnelCapture(1))));
  }
  const std::vector<std::string> lines = readLines(path);
  ASSERT_EQ(lines.size(), 2u);
  EXPECT_EQ(lines[0], "{\"earlier\":true}");
}

TEST(MetadataLogger, RotatesAtConfiguredSize) {
  const TempDir tmp;
  const fs::path path = tmp.path() / "metadata.jsonl";
  MetadataLogConfig cfg = logConfig(path);
  const std::size_t line_bytes = [&] {
    std::string json;
    google::protobuf::util::JsonPrintOptions options;
    options.preserve_proto_field_names = true;
    (void)google::protobuf::util::MessageToJsonString(toMetadataRecord(tunnelCapture(1), cfg, "inst"), &json, options);
    return json.size() + 1;
  }();
  cfg.rotate_bytes = 2 * line_bytes + 5;  // Two lines per file.
  cfg.keep_files = 2;
  {
    MetadataLogger logger(cfg, "inst");
    for (std::uint64_t id = 1; id <= 9; ++id) {
      ASSERT_TRUE(logger.write(frameOf(tunnelCapture(id))));
    }
  }
  // 9 lines, 2 per file: the current file has line 9, .1 has 7-8, .2 has 5-6, and 1-4 were deleted.
  EXPECT_EQ(readLines(path).size(), 1u);
  EXPECT_EQ(readLines(path.string() + ".1").size(), 2u);
  EXPECT_EQ(readLines(path.string() + ".2").size(), 2u);
  EXPECT_FALSE(fs::exists(path.string() + ".3"));
  llmfw::v1::MetadataRecord oldest;
  ASSERT_TRUE(google::protobuf::util::JsonStringToMessage(readLines(path.string() + ".2")[0], &oldest).ok());
  EXPECT_EQ(oldest.capture_id(), 5u);
  EXPECT_EQ(modeOf(path), 0600u);
}

TEST(MetadataLogger, KeepFilesZeroDiscardsFullFile) {
  const TempDir tmp;
  const fs::path path = tmp.path() / "metadata.jsonl";
  MetadataLogConfig cfg = logConfig(path);
  cfg.rotate_bytes = 1;  // Every line fills a file.
  cfg.keep_files = 0;
  {
    MetadataLogger logger(cfg, "inst");
    for (std::uint64_t id = 1; id <= 3; ++id) {
      ASSERT_TRUE(logger.write(frameOf(tunnelCapture(id))));
    }
  }
  const std::vector<std::string> lines = readLines(path);
  ASSERT_EQ(lines.size(), 1u) << "a line longer than rotate_bytes is still written, alone";
  EXPECT_FALSE(fs::exists(path.string() + ".1"));
}

TEST(MetadataLogger, RefusesSymlinkAtPath) {
  const TempDir tmp;
  const fs::path target = tmp.path() / "elsewhere.txt";
  std::ofstream(target) << "";
  const fs::path path = tmp.path() / "metadata.jsonl";
  fs::create_symlink(target, path);
  EXPECT_THROW(MetadataLogger(logConfig(path), "inst"), std::system_error);
}

TEST(MetadataLogger, WriteFailsAfterCloseAndTickReopens) {
  const TempDir tmp;
  const fs::path path = tmp.path() / "metadata.jsonl";
  MetadataLogger logger(logConfig(path), "inst");
  logger.close();
  EXPECT_FALSE(logger.write(frameOf(tunnelCapture(1))));
  logger.tick(std::chrono::steady_clock::now());
  EXPECT_TRUE(logger.write(frameOf(tunnelCapture(2))));
  EXPECT_EQ(readLines(path).size(), 1u);
}

}  // namespace
}  // namespace llmfw
