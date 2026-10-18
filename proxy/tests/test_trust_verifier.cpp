#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <memory>
#include <string>

#include <openssl/evp.h>
#include <openssl/x509v3.h>

#include <unistd.h>

#include "llmfw/setup_ca.hpp"
#include "llmfw/setup_leaf.hpp"
#include "llmfw/setup_x509.hpp"
#include "llmfw/trust_verifier.hpp"

namespace llmfw {
namespace {

namespace fs = std::filesystem;

/// A fresh temp directory, removed with everything in it when the object goes away.
class TempDir {
 public:
  TempDir() {
    std::string tmpl = (fs::temp_directory_path() / "llmfw-trust-XXXXXX").string();
    path_ = ::mkdtemp(tmpl.data());
  }
  ~TempDir() { fs::remove_all(path_); }
  TempDir(const TempDir&) = delete;
  TempDir& operator=(const TempDir&) = delete;
  [[nodiscard]] const fs::path& path() const { return path_; }

 private:
  fs::path path_;
};

/// A non-owning STACK_OF(X509) of the given certificates, leaf first.
struct Chain {
  explicit Chain(std::initializer_list<X509*> certs) : stack(sk_X509_new_null()) {
    for (X509* cert : certs) {
      sk_X509_push(stack, cert);
    }
  }
  ~Chain() { sk_X509_free(stack); }
  Chain(const Chain&) = delete;
  Chain& operator=(const Chain&) = delete;
  STACK_OF(X509)* stack;
};

setup::EphemeralCa testCa() {
  setup::CaSpec spec;
  spec.common_name = "llm-firewall local CA (trust test)";
  return setup::generateConstrainedCa(spec);
}

/// A bundle verifier that trusts only `ca`.
PemBundleTrustVerifier bundleTrusting(const TempDir& tmp, const setup::EphemeralCa& ca) {
  const fs::path bundle = tmp.path() / "bundle.pem";
  std::ofstream(bundle) << setup::caCertificatePem(ca);
  return PemBundleTrustVerifier(bundle);
}

/// A leaf signed by `ca`, bypassing issueLeaf's checks: given SAN and validity window relative to now.
X509Ptr handMadeLeaf(const setup::EphemeralCa& ca, const std::string& san, long not_before_s, long not_after_s) {
  const EvpPkeyPtr key(EVP_EC_gen("P-256"));
  X509Ptr cert(X509_new());
  X509_set_version(cert.get(), X509_VERSION_3);
  setup::setRandomSerial(*cert);
  X509_gmtime_adj(X509_getm_notBefore(cert.get()), not_before_s);
  X509_gmtime_adj(X509_getm_notAfter(cert.get()), not_after_s);
  X509_set_issuer_name(cert.get(), X509_get_subject_name(ca.cert.get()));
  X509_set_pubkey(cert.get(), key.get());
  setup::addExtension(*cert, *ca.cert, NID_ext_key_usage, "serverAuth");
  setup::addExtension(*cert, *ca.cert, NID_subject_alt_name, san);
  X509_sign(cert.get(), ca.key.get(), EVP_sha256());
  return cert;
}

TEST(PemBundleTrustVerifier, AcceptsALeafFromTheBundleCaForItsNames) {
  const TempDir tmp;
  const setup::EphemeralCa ca = testCa();
  const setup::IssuedLeaf leaf = setup::issueLeaf(ca, setup::LeafSpec{});
  const PemBundleTrustVerifier verifier = bundleTrusting(tmp, ca);
  const Chain chain{leaf.cert.get()};
  for (const char* host : {"claude.ai", "api.claude.ai", "anthropic.com", "api.anthropic.com"}) {
    const VerifyResult result = verifier.verify(chain.stack, host);
    EXPECT_TRUE(result.ok) << host << ": " << result.reason;
  }
}

TEST(PemBundleTrustVerifier, AcceptsAChainThatIncludesTheRoot) {
  const TempDir tmp;
  const setup::EphemeralCa ca = testCa();
  const setup::IssuedLeaf leaf = setup::issueLeaf(ca, setup::LeafSpec{});
  const Chain chain{leaf.cert.get(), ca.cert.get()};
  EXPECT_TRUE(bundleTrusting(tmp, ca).verify(chain.stack, "claude.ai").ok);
}

TEST(PemBundleTrustVerifier, RejectsAHostTheLeafDoesNotName) {
  const TempDir tmp;
  const setup::EphemeralCa ca = testCa();
  const setup::IssuedLeaf leaf = setup::issueLeaf(ca, setup::LeafSpec{});
  const PemBundleTrustVerifier verifier = bundleTrusting(tmp, ca);
  const Chain chain{leaf.cert.get()};
  for (const char* host : {"a.b.claude.ai", "example.com"}) {
    const VerifyResult result = verifier.verify(chain.stack, host);
    EXPECT_FALSE(result.ok) << host;
    EXPECT_FALSE(result.reason.empty()) << host;
  }
}

TEST(PemBundleTrustVerifier, RejectsALeafFromAnotherCa) {
  const TempDir tmp;
  const setup::EphemeralCa ca = testCa();
  const setup::EphemeralCa other = testCa();
  const setup::IssuedLeaf leaf = setup::issueLeaf(other, setup::LeafSpec{});
  const Chain chain{leaf.cert.get()};
  EXPECT_FALSE(bundleTrusting(tmp, ca).verify(chain.stack, "claude.ai").ok);
}

TEST(PemBundleTrustVerifier, MacOsEnforcesTheCaNameConstraints) {
  const TempDir tmp;
  const setup::EphemeralCa ca = testCa();
  const X509Ptr rogue = handMadeLeaf(ca, "DNS:example.com", 0, 86400);
  const Chain chain{rogue.get()};
  EXPECT_FALSE(bundleTrusting(tmp, ca).verify(chain.stack, "example.com").ok);
}

TEST(PemBundleTrustVerifier, RejectsAnExpiredLeaf) {
  const TempDir tmp;
  const setup::EphemeralCa ca = testCa();
  const X509Ptr expired = handMadeLeaf(ca, "DNS:claude.ai", -10 * 86400, -86400);
  const Chain chain{expired.get()};
  EXPECT_FALSE(bundleTrusting(tmp, ca).verify(chain.stack, "claude.ai").ok);
}

TEST(PemBundleTrustVerifier, RejectsAnEmptyChainOrHost) {
  const TempDir tmp;
  const setup::EphemeralCa ca = testCa();
  const setup::IssuedLeaf leaf = setup::issueLeaf(ca, setup::LeafSpec{});
  const PemBundleTrustVerifier verifier = bundleTrusting(tmp, ca);
  const Chain empty{};
  EXPECT_FALSE(verifier.verify(empty.stack, "claude.ai").ok);
  EXPECT_FALSE(verifier.verify(nullptr, "claude.ai").ok);
  const Chain chain{leaf.cert.get()};
  EXPECT_FALSE(verifier.verify(chain.stack, "").ok);
}

TEST(PemBundleTrustVerifier, RefusesAMissingOrEmptyBundle) {
  const TempDir tmp;
  EXPECT_THROW(PemBundleTrustVerifier(tmp.path() / "missing.pem"), ConfigError);
  std::ofstream(tmp.path() / "empty.pem") << "no certificates here\n";
  EXPECT_THROW(PemBundleTrustVerifier(tmp.path() / "empty.pem"), ConfigError);
}

TEST(SystemTrustVerifier, RejectsAChainFromAnUntrustedCa) {
  // The test CA is new and in no keychain, so system trust must refuse it.
  const setup::EphemeralCa ca = testCa();
  const setup::IssuedLeaf leaf = setup::issueLeaf(ca, setup::LeafSpec{});
  const Chain chain{leaf.cert.get(), ca.cert.get()};
  const VerifyResult result = SystemTrustVerifier().verify(chain.stack, "claude.ai");
  EXPECT_FALSE(result.ok);
  EXPECT_FALSE(result.reason.empty());
}

TEST(MakeTrustVerifier, PicksTheVerifierForTheMode) {
  const TempDir tmp;
  UpstreamConfig cfg;
  EXPECT_NE(dynamic_cast<const SystemTrustVerifier*>(makeTrustVerifier(cfg).get()), nullptr);

  const setup::EphemeralCa ca = testCa();
  cfg.trust = UpstreamTrustMode::kPemBundle;
  cfg.pem_bundle = tmp.path() / "bundle.pem";
  std::ofstream(cfg.pem_bundle) << setup::caCertificatePem(ca);
  EXPECT_NE(dynamic_cast<const PemBundleTrustVerifier*>(makeTrustVerifier(cfg).get()), nullptr);

  cfg.pem_bundle = tmp.path() / "missing.pem";
  EXPECT_THROW((void)makeTrustVerifier(cfg), ConfigError);
}

}  // namespace
}  // namespace llmfw
