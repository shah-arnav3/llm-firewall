#include <gtest/gtest.h>

#include <atomic>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <string>
#include <unistd.h>

#include "llmfw/config.hpp"

namespace llmfw {
namespace {

const std::filesystem::path kExampleConfig = std::filesystem::path(LLMFW_REPO_DIR) / "config" / "llm-firewall.yaml";

std::string readFile(const std::filesystem::path& path) {
  std::ifstream in(path);
  std::stringstream ss;
  ss << in.rdbuf();
  return ss.str();
}

/// Writes YAML to a unique temp file that is removed when the object goes away.
class TempConfig {
 public:
  explicit TempConfig(const std::string& yaml) {
    static std::atomic<int> counter{0};
    path_ = std::filesystem::temp_directory_path() /
            ("llmfw-config-" + std::to_string(getpid()) + "-" + std::to_string(counter++) + ".yaml");
    std::ofstream(path_) << yaml;
  }
  ~TempConfig() { std::filesystem::remove(path_); }
  TempConfig(const TempConfig&) = delete;
  TempConfig& operator=(const TempConfig&) = delete;

  [[nodiscard]] const std::filesystem::path& path() const { return path_; }

 private:
  std::filesystem::path path_;
};

/// The example config with every occurrence of `from` replaced by `to`. Fails the
/// test if `from` does not occur, so a change to the example cannot silently skip a case.
std::string exampleWith(const std::string& from, const std::string& to) {
  std::string yaml = readFile(kExampleConfig);
  const std::size_t at = yaml.find(from);
  EXPECT_NE(at, std::string::npos) << "example config no longer contains: " << from;
  if (at != std::string::npos) {
    yaml.replace(at, from.size(), to);
  }
  return yaml;
}

/// Loads YAML and returns the ConfigError message, or "" if it loaded.
std::string loadError(const std::string& yaml) {
  const TempConfig file(yaml);
  try {
    (void)loadProxyConfig(file.path());
  } catch (const ConfigError& e) {
    return e.what();
  }
  return "";
}

/// Sets $HOME for one test and restores it afterwards.
class ScopedHome {
 public:
  explicit ScopedHome(const char* home) {
    if (const char* old = std::getenv("HOME")) {
      old_ = old;
    }
    setenv("HOME", home, 1);
  }
  ~ScopedHome() { setenv("HOME", old_.c_str(), 1); }
  ScopedHome(const ScopedHome&) = delete;
  ScopedHome& operator=(const ScopedHome&) = delete;

 private:
  std::string old_;
};

TEST(Config, LoadsExampleConfigFromRepo) {
  const ProxyConfig cfg = loadProxyConfig(kExampleConfig);
  EXPECT_EQ(cfg.listen.address, "127.0.0.1");
  EXPECT_EQ(cfg.listen.port, 18443);
  EXPECT_EQ(cfg.listen.io_threads, 2u);
  EXPECT_EQ(cfg.listen.idle_timeout, std::chrono::milliseconds(300'000));
  EXPECT_EQ(cfg.mode, CaptureMode::kMetadataOnly);
  EXPECT_EQ(cfg.upstream.trust, UpstreamTrustMode::kSystem);
  EXPECT_EQ(cfg.decrypt_hosts, (std::vector<std::string>{"claude.ai", "*.claude.ai", "anthropic.com", "*.anthropic.com"}));
  ASSERT_EQ(cfg.clients.size(), 2u);
  EXPECT_EQ(cfg.clients[0].path, ClientPathTag::kClaudeCode);
  EXPECT_EQ(cfg.clients[1].path, ClientPathTag::kUi);
  EXPECT_EQ(cfg.capture.queue_max_bytes, 256u << 20);
  EXPECT_EQ(cfg.ipc.socketPath().filename(), "capture.sock");
  EXPECT_EQ(cfg.metadata_log.keep_files, 5u);
}

TEST(Config, ExpandsTildeToHome) {
  const ScopedHome home("/tmp/llmfw-home");
  const ProxyConfig cfg = loadProxyConfig(kExampleConfig);
  EXPECT_EQ(cfg.certs.dir, "/tmp/llmfw-home/Library/Application Support/llm-firewall/certs");
  EXPECT_EQ(cfg.ipc.socketPath(), "/tmp/llmfw-home/Library/Application Support/llm-firewall/run/capture.sock");
  EXPECT_EQ(cfg.metadata_log.path, "/tmp/llmfw-home/Library/Logs/llm-firewall/phase0-metadata.jsonl");
}

TEST(Config, AcceptsOtherLoopbackAddresses) {
  EXPECT_EQ(loadError(exampleWith("listen_address: 127.0.0.1", "listen_address: 127.0.0.2")), "");
  EXPECT_EQ(loadError(exampleWith("listen_address: 127.0.0.1", "listen_address: \"::1\"")), "");
}

TEST(Config, RejectsNonLoopbackListenAddress) {
  for (const char* address : {"0.0.0.0", "192.168.1.2", "localhost", "\"::\""}) {
    const std::string error = loadError(exampleWith("listen_address: 127.0.0.1", std::string("listen_address: ") + address));
    EXPECT_TRUE(error.starts_with("proxy.listen_address: must be a loopback address")) << address << ": " << error;
  }
}

TEST(Config, RejectsOutOfRangePort) {
  EXPECT_TRUE(loadError(exampleWith("listen_port: 18443", "listen_port: 0")).starts_with("proxy.listen_port:"));
  EXPECT_TRUE(loadError(exampleWith("listen_port: 18443", "listen_port: 70000")).starts_with("proxy.listen_port:"));
  EXPECT_TRUE(loadError(exampleWith("listen_port: 18443", "listen_port: abc")).starts_with("proxy.listen_port: must be an integer"));
}

TEST(Config, RejectsSocketPathLongerThan103Bytes) {
  const std::string long_dir(100, 'd');
  const std::string error =
      loadError(exampleWith("socket_dir: \"~/Library/Application Support/llm-firewall/run\"", "socket_dir: /" + long_dir));
  EXPECT_TRUE(error.starts_with("ipc.socket_dir: socket path is")) << error;
}

TEST(Config, RejectsMaxFrameBytesBelowBodyCaps) {
  const std::string error = loadError(exampleWith("max_frame_bytes: 20971520", "max_frame_bytes: 16777216"));
  EXPECT_TRUE(error.starts_with("ipc.max_frame_bytes: must be at least the largest body cap")) << error;
}

TEST(Config, RejectsMalformedDecryptHostPattern) {
  for (const char* pattern : {"\"*.ai\"", "\"api.*.claude.ai\"", "claude_ai.com", "127.0.0.1"}) {
    const std::string error = loadError(exampleWith("    - claude.ai\n", std::string("    - ") + pattern + "\n"));
    EXPECT_TRUE(error.starts_with("scope.decrypt_hosts: invalid pattern")) << pattern << ": " << error;
  }
}

TEST(Config, LowerCasesDecryptHosts) {
  const TempConfig file(exampleWith("    - claude.ai\n", "    - Claude.AI\n"));
  EXPECT_EQ(loadProxyConfig(file.path()).decrypt_hosts.front(), "claude.ai");
}

TEST(Config, LowerCasesRedactHeaderNames) {
  const TempConfig file(exampleWith("    - cookie\n", "    - Cookie\n"));
  const ProxyConfig cfg = loadProxyConfig(file.path());
  EXPECT_EQ(cfg.capture.redact_headers.front(), "cookie");
}

TEST(Config, DefaultsModeToMetadataOnly) {
  const TempConfig file(exampleWith("  mode: metadata_only\n", ""));
  EXPECT_EQ(loadProxyConfig(file.path()).mode, CaptureMode::kMetadataOnly);
}

TEST(Config, ParsesFullMode) {
  const TempConfig file(exampleWith("mode: metadata_only", "mode: full"));
  EXPECT_EQ(loadProxyConfig(file.path()).mode, CaptureMode::kFull);
}

TEST(Config, RejectsUnknownEnumValues) {
  EXPECT_TRUE(loadError(exampleWith("mode: metadata_only", "mode: verbose")).starts_with("proxy.mode:"));
  EXPECT_TRUE(loadError(exampleWith("trust: system", "trust: none")).starts_with("proxy.upstream.trust:"));
  EXPECT_TRUE(loadError(exampleWith("path: UI", "path: WEB")).starts_with("clients[1].path:"));
  EXPECT_TRUE(loadError(exampleWith("client_alpn: [\"http/1.1\"]", "client_alpn: [\"h2\"]")).starts_with("proxy.client_alpn:"));
}

TEST(Config, RequiresVersionOne) {
  EXPECT_EQ(loadError(exampleWith("version: 1", "version: 2")), "version: must be 1");
  EXPECT_EQ(loadError(exampleWith("version: 1", "")), "version: must be 1");
}

TEST(Config, RequiresPathsWithoutDefaults) {
  EXPECT_EQ(loadError(exampleWith("  path: \"~/Library/Logs/llm-firewall/phase0-metadata.jsonl\"\n", "")),
            "metadata_log.path: is required");
}

TEST(Config, RejectsNonPositiveSizes) {
  EXPECT_TRUE(loadError(exampleWith("queue_max_items: 1024", "queue_max_items: 0")).starts_with("capture.queue_max_items:"));
  EXPECT_TRUE(loadError(exampleWith("rotate_bytes: 52428800", "rotate_bytes: -1")).starts_with("metadata_log.rotate_bytes:"));
}

TEST(Config, ReportsUnreadableAndInvalidFiles) {
  const std::string empty = loadError("");
  EXPECT_TRUE(empty.ends_with("the top level must be a mapping")) << empty;
  EXPECT_TRUE(loadError("proxy: [unclosed").find("invalid YAML") != std::string::npos);
  try {
    (void)loadProxyConfig("/nonexistent/llm-firewall.yaml");
    FAIL() << "expected ConfigError";
  } catch (const ConfigError& e) {
    EXPECT_STREQ(e.what(), "/nonexistent/llm-firewall.yaml: cannot read the file");
  }
}

TEST(Config, DefaultConfigPathIsUnderApplicationSupport) {
  const ScopedHome home("/tmp/llmfw-home");
  EXPECT_EQ(defaultConfigPath(), "/tmp/llmfw-home/Library/Application Support/llm-firewall/llm-firewall.yaml");
}

}  // namespace
}  // namespace llmfw
