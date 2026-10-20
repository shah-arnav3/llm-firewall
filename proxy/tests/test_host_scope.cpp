#include <gtest/gtest.h>

#include <filesystem>
#include <optional>
#include <string>

#include <unistd.h>

#include "llmfw/cert_store.hpp"
#include "llmfw/host_scope.hpp"
#include "llmfw/setup_ca.hpp"
#include "llmfw/setup_leaf.hpp"
#include "llmfw/tls_breaker.hpp"

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

/// The production leaf (claude.ai, *.claude.ai, anthropic.com, *.anthropic.com), loaded as the proxy loads it.
class TestCerts {
 public:
  TestCerts() {
    std::string tmpl = (std::filesystem::temp_directory_path() / "llmfw-scope-XXXXXX").string();
    dir_ = ::mkdtemp(tmpl.data());
    setup::CaSpec spec;
    spec.common_name = "llm-firewall local CA (scope test)";
    const setup::EphemeralCa ca = setup::generateConstrainedCa(spec);
    setup::writeLeaf(setup::issueLeaf(ca, setup::LeafSpec{}), dir_ / "leaf.pem", dir_ / "leaf.key");
    CertConfig cfg;
    cfg.dir = dir_;
    store_.emplace(LeafCertStore::load(cfg));
  }
  ~TestCerts() { std::filesystem::remove_all(dir_); }
  TestCerts(const TestCerts&) = delete;
  TestCerts& operator=(const TestCerts&) = delete;
  [[nodiscard]] const LeafCertStore* store() const { return &*store_; }

 private:
  std::filesystem::path dir_;
  std::optional<LeafCertStore> store_;
};

const Clock::time_point kNow = Clock::time_point{} + std::chrono::hours{1};

TEST(DecideScope, CoveredScopedTlsHostIsDecrypted) {
  const TestCerts certs;
  for (const char* host : {"claude.ai", "API.claude.ai", "anthropic.com", "api.anthropic.com"}) {
    EXPECT_EQ(decideScope(host, 443, claudeScope(), certs.store(), nullptr, kNow).reason, TunnelReasonTag::kNone)
        << host;
  }
}

TEST(DecideScope, ScopedHostNoSanCoversIsTunneledWithoutCert) {
  // In scope through "*.claude.ai", but a wildcard SAN covers only one label.
  const TestCerts certs;
  EXPECT_EQ(decideScope("a.b.claude.ai", 443, claudeScope(), certs.store(), nullptr, kNow).reason,
            TunnelReasonTag::kScopedNoCert);
}

TEST(DecideScope, EarlierChecksWinOverCertificates) {
  const TestCerts certs;
  EXPECT_EQ(decideScope("example.com", 443, claudeScope(), certs.store(), nullptr, kNow).reason,
            TunnelReasonTag::kUnscopedHost);
  EXPECT_EQ(decideScope("claude.ai", 8443, claudeScope(), certs.store(), nullptr, kNow).reason,
            TunnelReasonTag::kNonTlsPort);
}

TEST(DecideScope, OpenBreakerTunnelsUntilItsCooldownEnds) {
  const TestCerts certs;
  ClientTlsBreaker breaker(std::chrono::milliseconds{1000});
  breaker.recordFailure("claude.ai", kNow);
  EXPECT_EQ(decideScope("claude.ai", 443, claudeScope(), certs.store(), &breaker, kNow).reason,
            TunnelReasonTag::kClientTlsBreaker);
  EXPECT_EQ(decideScope("api.claude.ai", 443, claudeScope(), certs.store(), &breaker, kNow).reason,
            TunnelReasonTag::kNone);
  EXPECT_EQ(decideScope("claude.ai", 443, claudeScope(), certs.store(), &breaker, kNow + std::chrono::seconds{1})
                .reason,
            TunnelReasonTag::kNone);
}

TEST(DecideScope, MissingCertsWinOverTheBreaker) {
  ClientTlsBreaker breaker(std::chrono::milliseconds{1000});
  breaker.recordFailure("claude.ai", kNow);
  EXPECT_EQ(decideScope("claude.ai", 443, claudeScope(), nullptr, &breaker, kNow).reason,
            TunnelReasonTag::kScopedNoCert);
}

}  // namespace
}  // namespace llmfw
