#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <sstream>

#include "llmfw/pac.hpp"

namespace llmfw {
namespace {

namespace fs = std::filesystem;

std::string readFile(const fs::path& path) {
  std::ifstream in(path);
  std::stringstream ss;
  ss << in.rdbuf();
  return ss.str();
}

TEST(PacTemplate, IsTheCommittedConfigFile) {
  EXPECT_EQ(pacTemplate(), readFile(fs::path(LLMFW_REPO_DIR) / "config" / "claude.pac"));
}

TEST(PacUrl, PointsAtThePacPath) {
  EXPECT_EQ(pacUrl("127.0.0.1", 18443), "http://127.0.0.1:18443/proxy.pac");
  EXPECT_EQ(pacUrl("::1", 18443), "http://[::1]:18443/proxy.pac");
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

}  // namespace
}  // namespace llmfw
