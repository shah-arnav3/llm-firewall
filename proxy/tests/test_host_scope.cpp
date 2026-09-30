#include <gtest/gtest.h>

#include "llmfw/host_scope.hpp"

namespace llmfw {
namespace {

HostScope claudeScope() {
  return HostScope({"claude.ai", "*.claude.ai", "anthropic.com", "*.anthropic.com"});
}

TEST(HostScope, ExactPatternMatchesOnlyThatName) {
  EXPECT_TRUE(HostScope::matchesPattern("claude.ai", "claude.ai"));
  EXPECT_FALSE(HostScope::matchesPattern("claude.ai", "api.claude.ai"));
  EXPECT_FALSE(HostScope::matchesPattern("claude.ai", "claude.ai.example.com"));
}

TEST(HostScope, WildcardMatchesSubdomainsButNotApex) {
  EXPECT_TRUE(HostScope::matchesPattern("*.claude.ai", "api.claude.ai"));
  EXPECT_TRUE(HostScope::matchesPattern("*.claude.ai", "a.b.claude.ai"));
  EXPECT_FALSE(HostScope::matchesPattern("*.claude.ai", "claude.ai"));
}

TEST(HostScope, WildcardDoesNotMatchLookalikeSuffix) {
  EXPECT_FALSE(HostScope::matchesPattern("*.claude.ai", "evilclaude.ai"));
  EXPECT_FALSE(claudeScope().inScope("evilclaude.ai"));
  EXPECT_FALSE(claudeScope().inScope("claude.ai.evil.com"));
}

TEST(HostScope, InScopeChecksEveryPattern) {
  const HostScope scope = claudeScope();
  EXPECT_TRUE(scope.inScope("claude.ai"));
  EXPECT_TRUE(scope.inScope("api.anthropic.com"));
  EXPECT_FALSE(scope.inScope("example.com"));
}

TEST(HostScope, NormalizeLowercasesAndStripsTrailingDot) {
  EXPECT_EQ(HostScope::normalizeHost("Claude.AI."), "claude.ai");
  EXPECT_EQ(HostScope::normalizeHost("api.claude.ai"), "api.claude.ai");
  EXPECT_EQ(HostScope::normalizeHost("claude.ai.."), std::nullopt);
}

TEST(HostScope, NormalizeRejectsIpLiterals) {
  EXPECT_EQ(HostScope::normalizeHost("127.0.0.1"), std::nullopt);
  EXPECT_EQ(HostScope::normalizeHost("::1"), std::nullopt);
  EXPECT_EQ(HostScope::normalizeHost("2606:4700::1"), std::nullopt);
}

TEST(HostScope, NormalizeRejectsOverlongLabels) {
  const std::string label63(63, 'a');
  EXPECT_TRUE(HostScope::normalizeHost(label63 + ".ai").has_value());
  EXPECT_EQ(HostScope::normalizeHost(label63 + "a.ai"), std::nullopt);
  EXPECT_EQ(HostScope::normalizeHost(std::string(254, 'a')), std::nullopt);
}

TEST(HostScope, NormalizeRejectsBadBytesAndEmptyLabels) {
  EXPECT_EQ(HostScope::normalizeHost(""), std::nullopt);
  EXPECT_EQ(HostScope::normalizeHost("clau de.ai"), std::nullopt);
  EXPECT_EQ(HostScope::normalizeHost("claude_ai.com"), std::nullopt);
  EXPECT_EQ(HostScope::normalizeHost("a..claude.ai"), std::nullopt);
  EXPECT_EQ(HostScope::normalizeHost("-claude.ai"), std::nullopt);
  EXPECT_EQ(HostScope::normalizeHost("claude-.ai"), std::nullopt);
}

TEST(HostScope, ValidPatterns) {
  EXPECT_TRUE(HostScope::isValidPattern("claude.ai"));
  EXPECT_TRUE(HostScope::isValidPattern("*.claude.ai"));
  EXPECT_FALSE(HostScope::isValidPattern("*.com"));
  EXPECT_FALSE(HostScope::isValidPattern("Claude.ai"));
  EXPECT_FALSE(HostScope::isValidPattern("*claude.ai"));
  EXPECT_FALSE(HostScope::isValidPattern("api.*.claude.ai"));
  EXPECT_FALSE(HostScope::isValidPattern("localhost"));
}

TEST(DecideScope, UnscopedHostIsTunneled) {
  const ScopeResult result = decideScope("Example.com", 443, claudeScope());
  EXPECT_EQ(result.reason, TunnelReasonTag::kUnscopedHost);
  EXPECT_EQ(result.normalized_host, "example.com");
}

TEST(DecideScope, InvalidHostIsUnscopedWithEmptyName) {
  const ScopeResult result = decideScope("127.0.0.1", 443, claudeScope());
  EXPECT_EQ(result.reason, TunnelReasonTag::kUnscopedHost);
  EXPECT_TRUE(result.normalized_host.empty());
}

TEST(DecideScope, NonTlsPortIsTunneled) {
  EXPECT_EQ(decideScope("claude.ai", 80, claudeScope()).reason, TunnelReasonTag::kNonTlsPort);
}

TEST(DecideScope, ScopedTlsHostIsTunneledWithoutCert) {
  const ScopeResult result = decideScope("CLAUDE.ai", 443, claudeScope());
  EXPECT_EQ(result.reason, TunnelReasonTag::kScopedNoCert);
  EXPECT_EQ(result.normalized_host, "claude.ai");
}

}  // namespace
}  // namespace llmfw
