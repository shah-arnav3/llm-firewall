#include <gtest/gtest.h>

#include <fstream>
#include <sstream>

#include <sys/stat.h>

#include "llmfw/setup_pac.hpp"

namespace llmfw::setup {
namespace {

namespace fs = std::filesystem;

std::string readFile(const fs::path& path) {
  std::ifstream in(path);
  std::stringstream ss;
  ss << in.rdbuf();
  return ss.str();
}

mode_t modeOf(const fs::path& path) {
  struct stat st {};
  EXPECT_EQ(::stat(path.c_str(), &st), 0) << path;
  return st.st_mode & 0777;
}

class TempDir {
 public:
  TempDir() {
    std::string tmpl = (fs::temp_directory_path() / "llmfw-pac-XXXXXX").string();
    path_ = ::mkdtemp(tmpl.data());
  }
  ~TempDir() { fs::remove_all(path_); }
  TempDir(const TempDir&) = delete;
  TempDir& operator=(const TempDir&) = delete;
  [[nodiscard]] const fs::path& path() const { return path_; }

 private:
  fs::path path_;
};

TEST(PacTemplate, IsTheCommittedConfigFile) {
  EXPECT_EQ(pacTemplate(), readFile(fs::path(LLMFW_REPO_DIR) / "config" / "claude.pac"));
}

TEST(RenderPac, ReplacesEveryPortToken) {
  const std::string pac = renderPac(pacTemplate(), 18443);
  EXPECT_EQ(pac.find("{{"), std::string::npos);
  EXPECT_NE(pac.find("return \"PROXY 127.0.0.1:18443; DIRECT\";"), std::string::npos)
      << "the fail-open DIRECT fallback must survive rendering";
}

TEST(RenderPac, ReplacesRepeatedTokens) {
  EXPECT_EQ(renderPac("a {{PROXY_PORT}} b {{PROXY_PORT}}", 9), "a 9 b 9");
}

TEST(RenderPac, FailsOnUnreplacedToken) {
  try {
    (void)renderPac("PROXY 127.0.0.1:{{PROXY_PORT}}; {{OTHER}}", 1);
    FAIL() << "expected TemplateError";
  } catch (const TemplateError& e) {
    EXPECT_STREQ(e.what(), "PAC template has an unreplaced token: {{OTHER}}");
  }
}

TEST(WritePacFile, CreatesPrivateParentsAndReadableFile) {
  const TempDir tmp;
  const fs::path pac_file = tmp.path() / "a" / "b" / "claude.pac";
  writePacFile(pac_file, "function FindProxyForURL() { return \"DIRECT\"; }\n");
  EXPECT_EQ(modeOf(tmp.path() / "a"), 0700u);
  EXPECT_EQ(modeOf(tmp.path() / "a" / "b"), 0700u);
  EXPECT_EQ(modeOf(pac_file), 0644u);
  EXPECT_EQ(readFile(pac_file), "function FindProxyForURL() { return \"DIRECT\"; }\n");
}

TEST(WritePacFile, ReplacesExistingFileAndLeavesNoTempFiles) {
  const TempDir tmp;
  const fs::path pac_file = tmp.path() / "claude.pac";
  writePacFile(pac_file, "old");
  writePacFile(pac_file, "new");
  EXPECT_EQ(readFile(pac_file), "new");
  std::size_t entries = 0;
  for ([[maybe_unused]] const auto& entry : fs::directory_iterator(tmp.path())) {
    ++entries;
  }
  EXPECT_EQ(entries, 1u);
}

TEST(WritePacFile, ThrowsWhenTheDirectoryCannotBeCreated) {
  EXPECT_THROW(writePacFile("/dev/null/llm-firewall/claude.pac", "x"), std::system_error);
}

}  // namespace
}  // namespace llmfw::setup
