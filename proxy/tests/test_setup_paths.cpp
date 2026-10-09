#include <gtest/gtest.h>

#include <cstdlib>
#include <string>

#include "llmfw/setup_paths.hpp"

namespace llmfw::setup {
namespace {

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

TEST(InstallPaths, ResolvesEverythingUnderHome) {
  const ScopedHome home("/Users/tester");
  const InstallPaths p = InstallPaths::forCurrentUser();
  EXPECT_EQ(p.home, "/Users/tester");
  EXPECT_EQ(p.app_support, "/Users/tester/Library/Application Support/llm-firewall");
  EXPECT_EQ(p.config_file, "/Users/tester/Library/Application Support/llm-firewall/llm-firewall.yaml");
  EXPECT_EQ(p.profile_file,
            "/Users/tester/Library/Application Support/llm-firewall/llm-firewall-claude-proxy.mobileconfig");
  EXPECT_EQ(p.leaf_key, "/Users/tester/Library/Application Support/llm-firewall/certs/leaf.key");
  EXPECT_EQ(p.logs_dir, "/Users/tester/Library/Logs/llm-firewall");
  EXPECT_EQ(p.proxy_plist, "/Users/tester/Library/LaunchAgents/dev.llmfirewall.proxy.plist");
}

TEST(InstallPaths, MatchesTheProxyDefaultConfigLocation) {
  const ScopedHome home("/Users/tester");
  EXPECT_EQ(InstallPaths::forCurrentUser().config_file,
            "/Users/tester/Library/Application Support/llm-firewall/llm-firewall.yaml");
}

TEST(InstallPaths, CreatesNothing) {
  const ScopedHome home("/nonexistent-llmfw-home");
  (void)InstallPaths::forCurrentUser();
  EXPECT_FALSE(std::filesystem::exists("/nonexistent-llmfw-home"));
}

}  // namespace
}  // namespace llmfw::setup
