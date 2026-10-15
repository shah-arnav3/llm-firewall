#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

#include <sys/stat.h>
#include <unistd.h>

#include "llmfw/setup_ca.hpp"
#include "llmfw/setup_leaf.hpp"
#include "llmfw/setup_x509.hpp"

namespace llmfw::setup {
namespace {

namespace fs = std::filesystem;

/// A fresh temp directory (mode 0700 from mkdtemp), removed with everything in it when the object goes away.
class TempDir {
 public:
  TempDir() {
    std::string tmpl = (fs::temp_directory_path() / "llmfw-leaf-XXXXXX").string();
    path_ = ::mkdtemp(tmpl.data());
  }
  ~TempDir() { fs::remove_all(path_); }
  TempDir(const TempDir&) = delete;
  TempDir& operator=(const TempDir&) = delete;
  [[nodiscard]] const fs::path& path() const { return path_; }

 private:
  fs::path path_;
};

EphemeralCa testCa() {
  CaSpec spec;
  spec.common_name = "llm-firewall local CA (test)";
  return generateConstrainedCa(spec);
}

std::vector<std::string> dnsSans(const X509& cert) {
  auto* names = static_cast<GENERAL_NAMES*>(X509_get_ext_d2i(&cert, NID_subject_alt_name, nullptr, nullptr));
  std::vector<std::string> out;
  for (int i = 0; i < sk_GENERAL_NAME_num(names); ++i) {
    const GENERAL_NAME* name = sk_GENERAL_NAME_value(names, i);
    EXPECT_EQ(name->type, GEN_DNS);
    if (name->type == GEN_DNS) {
      out.emplace_back(reinterpret_cast<const char*>(ASN1_STRING_get0_data(name->d.dNSName)),
                       static_cast<std::size_t>(ASN1_STRING_length(name->d.dNSName)));
    }
  }
  GENERAL_NAMES_free(names);
  return out;
}

/// X509_V_OK if `leaf` chains to `ca` and is valid for `host` (empty: skip the host check).
int verifyError(X509& leaf, X509& ca, const std::string& host) {
  X509_STORE* store = X509_STORE_new();
  X509_STORE_add_cert(store, &ca);
  X509_STORE_CTX* ctx = X509_STORE_CTX_new();
  X509_STORE_CTX_init(ctx, store, &leaf, nullptr);
  if (!host.empty()) {
    X509_VERIFY_PARAM_set1_host(X509_STORE_CTX_get0_param(ctx), host.c_str(), host.size());
  }
  X509_STORE_CTX_set_purpose(ctx, X509_PURPOSE_SSL_SERVER);
  const int result = X509_verify_cert(ctx);
  const int error = result == 1 ? X509_V_OK : X509_STORE_CTX_get_error(ctx);
  X509_STORE_CTX_free(ctx);
  X509_STORE_free(store);
  return error;
}

bool isCritical(const X509& cert, int nid) {
  const int index = X509_get_ext_by_NID(&cert, nid, -1);
  return index >= 0 && X509_EXTENSION_get_critical(X509_get_ext(&cert, index)) == 1;
}

std::string readFile(const fs::path& path) {
  std::ifstream in(path);
  std::ostringstream out;
  out << in.rdbuf();
  return out.str();
}

mode_t modeOf(const fs::path& path) {
  struct stat st {};
  EXPECT_EQ(::stat(path.c_str(), &st), 0) << path;
  return st.st_mode & 07777;
}

TEST(SetupLeaf, LeafHasExactlyFourSans) {
  const EphemeralCa ca = testCa();
  const IssuedLeaf leaf = issueLeaf(ca, LeafSpec{});
  const std::vector<std::string> expected{"claude.ai", "*.claude.ai", "anthropic.com", "*.anthropic.com"};
  EXPECT_EQ(dnsSans(*leaf.cert), expected);
}

TEST(SetupLeaf, LeafIsAServerCertificateAndNotACa) {
  const EphemeralCa ca = testCa();
  const IssuedLeaf leaf = issueLeaf(ca, LeafSpec{});
  X509* cert = leaf.cert.get();
  EXPECT_TRUE(isCritical(*cert, NID_basic_constraints));
  EXPECT_EQ(X509_get_extension_flags(cert) & EXFLAG_CA, 0u);
  EXPECT_TRUE(isCritical(*cert, NID_key_usage));
  EXPECT_EQ(X509_get_key_usage(cert), static_cast<std::uint32_t>(KU_DIGITAL_SIGNATURE));
  EXPECT_EQ(X509_get_extended_key_usage(cert), static_cast<std::uint32_t>(XKU_SSL_SERVER));
  EXPECT_EQ(X509_NAME_cmp(X509_get_issuer_name(cert), X509_get_subject_name(ca.cert.get())), 0);
}

TEST(SetupLeaf, LeafKeyIsAFreshP256Key) {
  const EphemeralCa ca = testCa();
  const IssuedLeaf leaf = issueLeaf(ca, LeafSpec{});
  char group[32] = {};
  ASSERT_EQ(EVP_PKEY_get_group_name(leaf.key.get(), group, sizeof group, nullptr), 1);
  EXPECT_STREQ(group, "prime256v1");
  EXPECT_NE(EVP_PKEY_eq(leaf.key.get(), ca.key.get()), 1);
  EXPECT_EQ(X509_check_private_key(leaf.cert.get(), leaf.key.get()), 1);
}

TEST(SetupLeaf, LeafValidityMatchesSpec) {
  const EphemeralCa ca = testCa();
  LeafSpec spec;
  spec.validity = std::chrono::days{90};
  const IssuedLeaf leaf = issueLeaf(ca, spec);
  int days = 0;
  int seconds = 0;
  ASSERT_EQ(
      ASN1_TIME_diff(&days, &seconds, X509_get0_notBefore(leaf.cert.get()), X509_get0_notAfter(leaf.cert.get())), 1);
  EXPECT_EQ(days, 90);
  EXPECT_EQ(seconds, 0);
}

TEST(SetupLeaf, LeafVerifiesAgainstCaForScopedNames) {
  const EphemeralCa ca = testCa();
  const IssuedLeaf leaf = issueLeaf(ca, LeafSpec{});
  for (const char* host : {"claude.ai", "api.claude.ai", "anthropic.com", "api.anthropic.com"}) {
    EXPECT_EQ(verifyError(*leaf.cert, *ca.cert, host), X509_V_OK) << host;
  }
  // A wildcard covers one label only, and nothing outside the SANs is covered.
  for (const char* host : {"a.b.claude.ai", "example.com", "claude.ai.example.com"}) {
    EXPECT_EQ(verifyError(*leaf.cert, *ca.cert, host), X509_V_ERR_HOSTNAME_MISMATCH) << host;
  }
}

TEST(SetupLeaf, CaCannotValidateLeafForOutOfScopeName) {
  // Signed by hand, bypassing issueLeaf's own check, to show the CA's Name
  // Constraints reject it in any verifier.
  const EphemeralCa ca = testCa();
  const EvpPkeyPtr key(EVP_EC_gen("P-256"));
  const X509Ptr rogue(X509_new());
  X509_set_version(rogue.get(), X509_VERSION_3);
  setRandomSerial(*rogue);
  setValidity(*rogue, std::chrono::days{30});
  X509_set_issuer_name(rogue.get(), X509_get_subject_name(ca.cert.get()));
  X509_set_pubkey(rogue.get(), key.get());
  addExtension(*rogue, *ca.cert, NID_subject_alt_name, "DNS:example.com");
  ASSERT_GT(X509_sign(rogue.get(), ca.key.get(), EVP_sha256()), 0);
  EXPECT_EQ(verifyError(*rogue, *ca.cert, ""), X509_V_ERR_PERMITTED_VIOLATION);
}

TEST(SetupLeaf, RefusesSansOutsideTheCaConstraints) {
  const EphemeralCa ca = testCa();
  LeafSpec spec;
  spec.dns_sans = {"claude.ai", "example.com"};
  EXPECT_THROW((void)issueLeaf(ca, spec), std::runtime_error);
}

TEST(SetupLeaf, RejectsInvalidSpecs) {
  const EphemeralCa ca = testCa();
  for (const std::vector<std::string>& sans : std::vector<std::vector<std::string>>{
           {}, {"*.ai"}, {"claude.ai,DNS:example.com"}, {"Claude.ai"}, {"10.0.0.1"}, {"*"}}) {
    LeafSpec spec;
    spec.dns_sans = sans;
    EXPECT_THROW((void)issueLeaf(ca, spec), std::invalid_argument) << (sans.empty() ? "<empty>" : sans[0]);
  }
  for (const int days : {0, 398}) {
    LeafSpec spec;
    spec.validity = std::chrono::days{days};
    EXPECT_THROW((void)issueLeaf(ca, spec), std::invalid_argument) << days;
  }
}

TEST(SetupLeaf, IssueAfterDestroyThrows) {
  EphemeralCa ca = testCa();
  destroyCaKey(ca);
  EXPECT_THROW((void)issueLeaf(ca, LeafSpec{}), std::invalid_argument);
}

TEST(SetupLeaf, WritesKeyWithMode0600AndCertWithMode0644) {
  const TempDir tmp;
  const EphemeralCa ca = testCa();
  const IssuedLeaf leaf = issueLeaf(ca, LeafSpec{});
  writeLeaf(leaf, tmp.path() / "leaf.pem", tmp.path() / "leaf.key");
  EXPECT_EQ(modeOf(tmp.path() / "leaf.key"), 0600u);
  EXPECT_EQ(modeOf(tmp.path() / "leaf.pem"), 0644u);
}

TEST(SetupLeaf, WrittenFilesLoadAsAMatchingPair) {
  const TempDir tmp;
  const EphemeralCa ca = testCa();
  const IssuedLeaf leaf = issueLeaf(ca, LeafSpec{});
  writeLeaf(leaf, tmp.path() / "leaf.pem", tmp.path() / "leaf.key");

  const std::string key_pem = readFile(tmp.path() / "leaf.key");
  EXPECT_EQ(key_pem.rfind("-----BEGIN PRIVATE KEY-----\n", 0), 0u) << "expected unencrypted PKCS#8";
  const std::string cert_pem = readFile(tmp.path() / "leaf.pem");
  EXPECT_EQ(cert_pem.find("PRIVATE KEY"), std::string::npos);

  const BioPtr key_bio(BIO_new_mem_buf(key_pem.data(), static_cast<int>(key_pem.size())));
  const EvpPkeyPtr key(PEM_read_bio_PrivateKey(key_bio.get(), nullptr, nullptr, nullptr));
  const BioPtr cert_bio(BIO_new_mem_buf(cert_pem.data(), static_cast<int>(cert_pem.size())));
  const X509Ptr cert(PEM_read_bio_X509(cert_bio.get(), nullptr, nullptr, nullptr));
  ASSERT_NE(key, nullptr);
  ASSERT_NE(cert, nullptr);
  EXPECT_EQ(X509_cmp(cert.get(), leaf.cert.get()), 0);
  EXPECT_EQ(X509_check_private_key(cert.get(), key.get()), 1);
}

TEST(SetupLeaf, RewriteReplacesBothFiles) {
  const TempDir tmp;
  const EphemeralCa ca = testCa();
  writeLeaf(issueLeaf(ca, LeafSpec{}), tmp.path() / "leaf.pem", tmp.path() / "leaf.key");
  const std::string first = readFile(tmp.path() / "leaf.pem");
  writeLeaf(issueLeaf(ca, LeafSpec{}), tmp.path() / "leaf.pem", tmp.path() / "leaf.key");
  EXPECT_NE(readFile(tmp.path() / "leaf.pem"), first);
  EXPECT_EQ(std::distance(fs::directory_iterator(tmp.path()), fs::directory_iterator{}), 2) << "no temp files left";
}

TEST(SetupLeaf, RefusesADirectoryThatIsNotPrivate) {
  const TempDir tmp;
  const EphemeralCa ca = testCa();
  const IssuedLeaf leaf = issueLeaf(ca, LeafSpec{});
  ASSERT_EQ(::chmod(tmp.path().c_str(), 0755), 0);
  EXPECT_THROW(writeLeaf(leaf, tmp.path() / "leaf.pem", tmp.path() / "leaf.key"), std::runtime_error);
  EXPECT_FALSE(fs::exists(tmp.path() / "leaf.key"));
  EXPECT_FALSE(fs::exists(tmp.path() / "leaf.pem"));
}

TEST(SetupLeaf, RefusesAMissingDirectory) {
  const TempDir tmp;
  const EphemeralCa ca = testCa();
  const IssuedLeaf leaf = issueLeaf(ca, LeafSpec{});
  EXPECT_THROW(writeLeaf(leaf, tmp.path() / "nope" / "leaf.pem", tmp.path() / "nope" / "leaf.key"),
               std::runtime_error);
}

}  // namespace
}  // namespace llmfw::setup
