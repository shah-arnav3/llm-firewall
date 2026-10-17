#include <gtest/gtest.h>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

#include <sys/stat.h>
#include <unistd.h>

#include "llmfw/cert_store.hpp"
#include "llmfw/setup_ca.hpp"
#include "llmfw/setup_leaf.hpp"
#include "llmfw/setup_x509.hpp"

namespace llmfw {
namespace {

namespace fs = std::filesystem;

/// A fresh temp directory (mode 0700 from mkdtemp), removed with everything in it when the object goes away.
class TempDir {
 public:
  TempDir() {
    std::string tmpl = (fs::temp_directory_path() / "llmfw-certs-XXXXXX").string();
    path_ = ::mkdtemp(tmpl.data());
  }
  ~TempDir() {
    ::chmod(path_.c_str(), 0700);
    fs::remove_all(path_);
  }
  TempDir(const TempDir&) = delete;
  TempDir& operator=(const TempDir&) = delete;
  [[nodiscard]] const fs::path& path() const { return path_; }

 private:
  fs::path path_;
};

CertConfig configFor(const fs::path& dir) {
  CertConfig cfg;
  cfg.dir = dir;
  return cfg;
}

setup::EphemeralCa testCa() {
  setup::CaSpec spec;
  spec.common_name = "llm-firewall local CA (test)";
  return setup::generateConstrainedCa(spec);
}

/// Writes a CA-issued leaf with the default four SANs into dir, as llmfw-setup certs does.
setup::IssuedLeaf writeTestLeaf(const fs::path& dir) {
  const setup::EphemeralCa ca = testCa();
  setup::IssuedLeaf leaf = setup::issueLeaf(ca, setup::LeafSpec{});
  setup::writeLeaf(leaf, dir / "leaf.pem", dir / "leaf.key");
  return leaf;
}

/// Writes a self-signed certificate with the given validity window (relative to now)
/// and SAN extension value (empty: no SAN), plus its key, bypassing issueLeaf's checks.
void writeHandMadeLeaf(const fs::path& dir, long not_before_s, long not_after_s, const std::string& san) {
  const EvpPkeyPtr key(EVP_EC_gen("P-256"));
  const X509Ptr cert(X509_new());
  X509_set_version(cert.get(), X509_VERSION_3);
  setup::setRandomSerial(*cert);
  X509_gmtime_adj(X509_getm_notBefore(cert.get()), not_before_s);
  X509_gmtime_adj(X509_getm_notAfter(cert.get()), not_after_s);
  X509_set_pubkey(cert.get(), key.get());
  if (!san.empty()) {
    setup::addExtension(*cert, *cert, NID_subject_alt_name, san);
  }
  ASSERT_GT(X509_sign(cert.get(), key.get(), EVP_sha256()), 0);
  setup::writeLeaf(setup::IssuedLeaf{X509Ptr(X509_dup(cert.get())), EvpPkeyPtr(EVP_PKEY_dup(key.get()))},
                   dir / "leaf.pem", dir / "leaf.key");
}

void expectLoadFails(const fs::path& dir, const std::string& fragment) {
  try {
    (void)LeafCertStore::load(configFor(dir));
    ADD_FAILURE() << "expected CertStoreError containing \"" << fragment << "\"";
  } catch (const CertStoreError& e) {
    EXPECT_NE(std::string(e.what()).find(fragment), std::string::npos) << e.what();
  }
}

TEST(LeafCertStore, LoadsTheFilesSetupWrites) {
  const TempDir tmp;
  const setup::IssuedLeaf leaf = writeTestLeaf(tmp.path());
  const LeafCertStore store = LeafCertStore::load(configFor(tmp.path()));
  EXPECT_EQ(X509_cmp(&store.certificate(), leaf.cert.get()), 0);
  EXPECT_EQ(EVP_PKEY_eq(&store.privateKey(), leaf.key.get()), 1);
  const std::vector<std::string> expected{"claude.ai", "*.claude.ai", "anthropic.com", "*.anthropic.com"};
  EXPECT_EQ(store.dnsNames(), expected);
}

TEST(LeafCertStore, NotAfterMatchesTheCertificate) {
  const TempDir tmp;
  writeTestLeaf(tmp.path());
  const LeafCertStore store = LeafCertStore::load(configFor(tmp.path()));
  const auto expected = std::chrono::system_clock::now() + std::chrono::days{397};
  EXPECT_LT(std::chrono::abs(store.notAfter() - expected), std::chrono::minutes{1});
}

TEST(LeafCertStore, CoversExactNamesAndOneWildcardLabel) {
  const TempDir tmp;
  writeTestLeaf(tmp.path());
  const LeafCertStore store = LeafCertStore::load(configFor(tmp.path()));
  for (const char* host : {"claude.ai", "api.claude.ai", "anthropic.com", "api.anthropic.com"}) {
    EXPECT_TRUE(store.covers(host)) << host;
  }
  for (const char* host :
       {"", "a.b.claude.ai", "example.com", "claude.ai.example.com", "evilclaude.ai", ".claude.ai", "ai"}) {
    EXPECT_FALSE(store.covers(host)) << host;
  }
}

TEST(LeafCertStore, RefusesADirectoryThatIsNotPrivate) {
  const TempDir tmp;
  writeTestLeaf(tmp.path());
  ASSERT_EQ(::chmod(tmp.path().c_str(), 0755), 0);
  expectLoadFails(tmp.path(), "mode 0700");
}

TEST(LeafCertStore, RefusesAMissingDirectory) {
  const TempDir tmp;
  expectLoadFails(tmp.path() / "nope", "cannot read");
}

TEST(LeafCertStore, RefusesAKeyReadableByOthers) {
  const TempDir tmp;
  writeTestLeaf(tmp.path());
  ASSERT_EQ(::chmod((tmp.path() / "leaf.key").c_str(), 0644), 0);
  expectLoadFails(tmp.path(), "mode 0600");
}

TEST(LeafCertStore, RefusesMissingFiles) {
  const TempDir tmp;
  writeTestLeaf(tmp.path());
  fs::remove(tmp.path() / "leaf.key");
  expectLoadFails(tmp.path(), "leaf.key");
  fs::remove(tmp.path() / "leaf.pem");
  expectLoadFails(tmp.path(), "leaf.pem");
}

TEST(LeafCertStore, RefusesSymlinks) {
  const TempDir tmp;
  const TempDir other;
  writeTestLeaf(other.path());
  writeTestLeaf(tmp.path());
  fs::remove(tmp.path() / "leaf.key");
  fs::create_symlink(other.path() / "leaf.key", tmp.path() / "leaf.key");
  expectLoadFails(tmp.path(), "leaf.key");

  const TempDir third;
  writeTestLeaf(third.path());
  fs::remove(third.path() / "leaf.pem");
  fs::create_symlink(other.path() / "leaf.pem", third.path() / "leaf.pem");
  expectLoadFails(third.path(), "leaf.pem");
}

TEST(LeafCertStore, RefusesAKeyThatDoesNotMatch) {
  const TempDir tmp;
  const TempDir other;
  writeTestLeaf(tmp.path());
  writeTestLeaf(other.path());
  fs::copy_file(other.path() / "leaf.key", tmp.path() / "leaf.key", fs::copy_options::overwrite_existing);
  ASSERT_EQ(::chmod((tmp.path() / "leaf.key").c_str(), 0600), 0);
  expectLoadFails(tmp.path(), "does not match");
}

TEST(LeafCertStore, RefusesFilesThatDoNotParse) {
  const TempDir tmp;
  writeTestLeaf(tmp.path());
  std::ofstream(tmp.path() / "leaf.pem", std::ios::trunc) << "not a certificate\n";
  expectLoadFails(tmp.path(), "is not a PEM certificate");

  const TempDir tmp2;
  writeTestLeaf(tmp2.path());
  std::ofstream(tmp2.path() / "leaf.key", std::ios::trunc) << "not a key\n";
  expectLoadFails(tmp2.path(), "is not an unencrypted PEM private key");
}

TEST(LeafCertStore, RefusesAnExpiredCertificate) {
  const TempDir tmp;
  writeHandMadeLeaf(tmp.path(), -10 * 86400, -86400, "DNS:claude.ai");
  expectLoadFails(tmp.path(), "has expired");
}

TEST(LeafCertStore, RefusesACertificateNotValidYet) {
  const TempDir tmp;
  writeHandMadeLeaf(tmp.path(), 86400, 10 * 86400, "DNS:claude.ai");
  expectLoadFails(tmp.path(), "not valid yet");
}

TEST(LeafCertStore, RefusesACertificateWithoutDnsNames) {
  const TempDir tmp;
  writeHandMadeLeaf(tmp.path(), 0, 86400, "");
  expectLoadFails(tmp.path(), "has no DNS names");
}

TEST(LeafCertStore, LowerCasesSanNames) {
  const TempDir tmp;
  writeHandMadeLeaf(tmp.path(), 0, 86400, "DNS:Claude.AI,IP:127.0.0.1");
  const LeafCertStore store = LeafCertStore::load(configFor(tmp.path()));
  EXPECT_EQ(store.dnsNames(), std::vector<std::string>{"claude.ai"});
  EXPECT_TRUE(store.covers("claude.ai"));
}

}  // namespace
}  // namespace llmfw
