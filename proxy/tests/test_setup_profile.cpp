#include <gtest/gtest.h>

#include <cstdio>
#include <regex>
#include <string>

#include <sys/stat.h>
#include <unistd.h>

#include "llmfw/fs_util.hpp"
#include "llmfw/setup_profile.hpp"

namespace llmfw::setup {
namespace {

namespace fs = std::filesystem;

const std::string kPacUrl = "http://127.0.0.1:18443/proxy.pac";
const std::string kProfileUuid = "11111111-1111-4111-8111-111111111111";
const std::string kPayloadUuid = "22222222-2222-4222-8222-222222222222";

class TempDir {
 public:
  TempDir() {
    std::string tmpl = (fs::temp_directory_path() / "llmfw-profile-XXXXXX").string();
    path_ = ::mkdtemp(tmpl.data());
  }
  ~TempDir() { fs::remove_all(path_); }
  TempDir(const TempDir&) = delete;
  TempDir& operator=(const TempDir&) = delete;
  [[nodiscard]] const fs::path& path() const { return path_; }

 private:
  fs::path path_;
};

/// Runs a command and returns its stdout, or "<exit N>" if it failed.
std::string run(const std::string& command) {
  std::string out;
  if (std::FILE* pipe = ::popen((command + " 2>/dev/null").c_str(), "r")) {
    char buf[4096];
    for (std::size_t n; (n = std::fread(buf, 1, sizeof buf, pipe)) > 0;) {
      out.append(buf, n);
    }
    const int status = ::pclose(pipe);
    if (status != 0) {
      return "<exit " + std::to_string(status) + ">";
    }
  }
  return out;
}

/// What macOS's plist parser reads at `key_path` in the profile.
std::string extract(const fs::path& profile, const std::string& key_path) {
  return run("/usr/bin/plutil -extract '" + key_path + "' raw -o - '" + profile.string() + "'");
}

fs::path writeTemp(const TempDir& tmp, const std::string& xml) {
  const fs::path path = tmp.path() / "profile.mobileconfig";
  writeProfile(path, xml);
  return path;
}

TEST(EgressProxyProfile, IsAValidPlist) {
  const TempDir tmp;
  const fs::path path = writeTemp(tmp, buildEgressProxyProfile(kPacUrl, ProfileScope::kUser, kProfileUuid, kPayloadUuid));
  EXPECT_NE(run("/usr/bin/plutil -lint '" + path.string() + "'").find(": OK"), std::string::npos);
}

TEST(EgressProxyProfile, CarriesOnlyThePacUrlForClaude) {
  const TempDir tmp;
  const fs::path path = writeTemp(tmp, buildEgressProxyProfile(kPacUrl, ProfileScope::kUser, kProfileUuid, kPayloadUuid));
  EXPECT_EQ(extract(path, "PayloadType"), "Configuration\n");
  EXPECT_EQ(extract(path, "PayloadIdentifier"), "dev.llmfirewall.claude-egress-proxy\n");
  EXPECT_EQ(extract(path, "PayloadUUID"), kProfileUuid + "\n");
  EXPECT_EQ(extract(path, "PayloadScope"), "User\n");
  EXPECT_EQ(extract(path, "PayloadContent.0.PayloadType"), "com.anthropic.claudefordesktop\n");
  EXPECT_EQ(extract(path, "PayloadContent.0.PayloadUUID"), kPayloadUuid + "\n");
  EXPECT_EQ(extract(path, "PayloadContent.0.egressProxyPacUrl"), kPacUrl + "\n");
  EXPECT_EQ(extract(path, "PayloadContent.1"), "<exit 256>") << "exactly one payload";

  // Any key that reaches Claude (not Payload*) other than egressProxyPacUrl would take
  // over more than its proxy.
  const std::string json = run("/usr/bin/plutil -extract PayloadContent.0 json -o - '" + path.string() + "'");
  std::smatch match;
  std::string rest = json;
  std::vector<std::string> app_keys;
  const std::regex key("\"([A-Za-z0-9_]+)\":");
  while (std::regex_search(rest, match, key)) {
    if (!match[1].str().starts_with("Payload")) {
      app_keys.push_back(match[1]);
    }
    rest = match.suffix();
  }
  EXPECT_EQ(app_keys, (std::vector<std::string>{"egressProxyPacUrl"})) << json;
}

TEST(EgressProxyProfile, SystemScope) {
  const TempDir tmp;
  const fs::path path =
      writeTemp(tmp, buildEgressProxyProfile(kPacUrl, ProfileScope::kSystem, kProfileUuid, kPayloadUuid));
  EXPECT_EQ(extract(path, "PayloadScope"), "System\n");
}

TEST(EgressProxyProfile, EscapesXmlInValues) {
  const TempDir tmp;
  const std::string url = "http://127.0.0.1:1/p.pac?a=1&b=<2>\"'";
  const fs::path path = writeTemp(tmp, buildEgressProxyProfile(url, ProfileScope::kUser, kProfileUuid, kPayloadUuid));
  EXPECT_EQ(extract(path, "PayloadContent.0.egressProxyPacUrl"), url + "\n");
}

TEST(WriteProfile, CreatesPrivateParentsAndReadableFile) {
  const TempDir tmp;
  const fs::path path = tmp.path() / "a" / "profile.mobileconfig";
  writeProfile(path, "x");
  struct stat dir {}, file {};
  ASSERT_EQ(::stat((tmp.path() / "a").c_str(), &dir), 0);
  ASSERT_EQ(::stat(path.c_str(), &file), 0);
  EXPECT_EQ(dir.st_mode & 0777, 0700u);
  EXPECT_EQ(file.st_mode & 0777, 0644u);
}

}  // namespace
}  // namespace llmfw::setup
