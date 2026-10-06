#include <gtest/gtest.h>

#include <chrono>
#include <cstdlib>
#include <fstream>
#include <string>
#include <thread>
#include <vector>

#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

#include "llmfw/setup_launcher.hpp"

namespace llmfw::setup {
namespace {

namespace fs = std::filesystem;
using std::chrono::milliseconds;

class TempDir {
 public:
  TempDir() {
    std::string tmpl = (fs::temp_directory_path() / "llmfw-launch-XXXXXX").string();
    path_ = ::mkdtemp(tmpl.data());
  }
  ~TempDir() { fs::remove_all(path_); }
  TempDir(const TempDir&) = delete;
  TempDir& operator=(const TempDir&) = delete;
  [[nodiscard]] const fs::path& path() const { return path_; }

 private:
  fs::path path_;
};

/// A Claude.app-shaped bundle whose executable is the fake_claude test helper.
fs::path makeFakeApp(const fs::path& dir) {
  const fs::path app = dir / "Claude.app";
  fs::create_directories(app / "Contents" / "MacOS");
  fs::copy_file(LLMFW_FAKE_CLAUDE, app / "Contents" / "MacOS" / "Claude");
  return app;
}

/// Sets environment variables for one test and removes them afterwards.
class ScopedEnv {
 public:
  void set(const char* name, const std::string& value) {
    setenv(name, value.c_str(), 1);
    names_.push_back(name);
  }
  ~ScopedEnv() {
    for (const char* name : names_) {
      unsetenv(name);
    }
  }

 private:
  std::vector<const char*> names_;
};

std::vector<std::string> waitForLines(const fs::path& path) {
  for (int attempt = 0; attempt < 500 && !fs::exists(path); ++attempt) {
    std::this_thread::sleep_for(milliseconds(10));
  }
  std::vector<std::string> lines;
  std::ifstream in(path);
  for (std::string line; std::getline(in, line);) {
    lines.push_back(line);
  }
  return lines;
}

void reap(pid_t pid) {
  int status = 0;
  ::waitpid(pid, &status, 0);
}

std::string base64Decode(std::string_view in) {
  static constexpr std::string_view kAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string out;
  unsigned buffer = 0;
  int bits = 0;
  for (const char c : in) {
    if (c == '=') {
      break;
    }
    buffer = (buffer << 6) | static_cast<unsigned>(kAlphabet.find(c));
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push_back(static_cast<char>((buffer >> bits) & 0xff));
    }
  }
  return out;
}

TEST(FileUrl, PercentEncodesSpacesAndKeepsSlashes) {
  EXPECT_EQ(fileUrl("/Users/a/Library/Application Support/llm-firewall/claude.pac"),
            "file:///Users/a/Library/Application%20Support/llm-firewall/claude.pac");
  EXPECT_EQ(fileUrl("/tmp/a#b?c%d"), "file:///tmp/a%23b%3Fc%25d");
  EXPECT_EQ(fileUrl("/tmp/caf\xc3\xa9"), "file:///tmp/caf%C3%A9");
}

TEST(DataUrl, EncodesThePacAsBase64) {
  const std::string prefix = "data:application/x-ns-proxy-autoconfig;base64,";
  for (const std::string& pac : {std::string("function FindProxyForURL(u, h) { return \"DIRECT\"; }"),
                                std::string("a"), std::string("ab"), std::string("abc"), std::string()}) {
    const std::string url = dataUrl(pac);
    ASSERT_TRUE(url.starts_with(prefix)) << url;
    EXPECT_EQ(base64Decode(url.substr(prefix.size())), pac);
  }
  EXPECT_EQ(dataUrl("ab"), prefix + "YWI=");
  EXPECT_EQ(dataUrl("a"), prefix + "YQ==");
}

TEST(BuildLaunchSpec, PassesOnlyThePacUrlFlag) {
  const LaunchSpec spec = buildLaunchSpec("/Applications/Claude.app", "file:///x/claude.pac");
  EXPECT_EQ(spec.executable, "/Applications/Claude.app/Contents/MacOS/Claude");
  EXPECT_EQ(spec.args, (std::vector<std::string>{"--proxy-pac-url=file:///x/claude.pac"}));
}

TEST(LaunchDetached, StartsTheExecutableWithItsArguments) {
  const TempDir tmp;
  const fs::path out = tmp.path() / "args.txt";
  ScopedEnv env;
  env.set("LLMFW_FAKE_CLAUDE_OUT", out.string());
  const pid_t pid = launchDetached(buildLaunchSpec(makeFakeApp(tmp.path()), "file:///x/claude.pac"));
  EXPECT_GT(pid, 0);
  EXPECT_EQ(waitForLines(out), (std::vector<std::string>{"--proxy-pac-url=file:///x/claude.pac"}));
  reap(pid);
}

TEST(LaunchDetached, RunsInANewSession) {
  const TempDir tmp;
  ScopedEnv env;
  env.set("LLMFW_FAKE_CLAUDE_SLEEP_MS", "2000");
  const pid_t pid = launchDetached(buildLaunchSpec(makeFakeApp(tmp.path()), "x"));
  ASSERT_GT(pid, 0);
  EXPECT_EQ(::getsid(pid), pid) << "the child should lead its own session";
  EXPECT_NE(::getsid(pid), ::getsid(0));
  ::kill(pid, SIGTERM);
  reap(pid);
}

TEST(LaunchDetached, ThrowsWhenTheExecutableIsMissing) {
  EXPECT_THROW((void)launchDetached(buildLaunchSpec("/nonexistent/Claude.app", "x")), std::system_error);
}

TEST(RunningProcessesAt, FindsOnlyProcessesOfThatExecutable) {
  const TempDir tmp;
  const fs::path app = makeFakeApp(tmp.path());
  const fs::path executable = app / "Contents" / "MacOS" / "Claude";
  EXPECT_TRUE(runningProcessesAt(executable).empty());

  ScopedEnv env;
  env.set("LLMFW_FAKE_CLAUDE_SLEEP_MS", "3000");
  const pid_t pid = launchDetached(buildLaunchSpec(app, "x"));
  std::vector<pid_t> found;
  for (int attempt = 0; attempt < 100 && found.empty(); ++attempt) {
    found = runningProcessesAt(executable);
    std::this_thread::sleep_for(milliseconds(10));
  }
  EXPECT_EQ(found, (std::vector<pid_t>{pid}));
  EXPECT_TRUE(runningProcessesAt(tmp.path() / "Other.app" / "Contents" / "MacOS" / "Claude").empty());
  ::kill(pid, SIGTERM);
  reap(pid);
}

TEST(RunningProcessesAt, ResolvesSymlinkedPaths) {
  const TempDir tmp;
  const fs::path app = makeFakeApp(tmp.path());
  fs::create_directory_symlink(app, tmp.path() / "Link.app");
  ScopedEnv env;
  env.set("LLMFW_FAKE_CLAUDE_SLEEP_MS", "3000");
  const pid_t pid = launchDetached(buildLaunchSpec(app, "x"));
  std::vector<pid_t> found;
  for (int attempt = 0; attempt < 100 && found.empty(); ++attempt) {
    found = runningProcessesAt(tmp.path() / "Link.app" / "Contents" / "MacOS" / "Claude");
    std::this_thread::sleep_for(milliseconds(10));
  }
  EXPECT_EQ(found, (std::vector<pid_t>{pid}));
  ::kill(pid, SIGTERM);
  reap(pid);
}

}  // namespace
}  // namespace llmfw::setup
