#include <gtest/gtest.h>

#include <stdexcept>
#include <string>
#include <vector>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

#include "llmfw/setup_ca.hpp"
#include "llmfw/setup_leaf.hpp"
#include "llmfw/setup_x509.hpp"

namespace llmfw::setup {
namespace {

CaSpec testSpec() {
  CaSpec spec;
  spec.common_name = "llm-firewall local CA (test)";
  return spec;
}

bool isCritical(const X509& cert, int nid) {
  const int index = X509_get_ext_by_NID(&cert, nid, -1);
  return index >= 0 && X509_EXTENSION_get_critical(X509_get_ext(&cert, index)) == 1;
}

/// The constraint subtrees of one kind, as (type, value) where value is the DNS name or the raw IP bytes.
std::vector<std::pair<int, std::string>> subtrees(const X509& cert, bool permitted) {
  auto* nc = static_cast<NAME_CONSTRAINTS*>(X509_get_ext_d2i(&cert, NID_name_constraints, nullptr, nullptr));
  std::vector<std::pair<int, std::string>> out;
  if (nc == nullptr) {
    return out;
  }
  STACK_OF(GENERAL_SUBTREE)* list = permitted ? nc->permittedSubtrees : nc->excludedSubtrees;
  for (int i = 0; i < sk_GENERAL_SUBTREE_num(list); ++i) {
    const GENERAL_NAME* name = sk_GENERAL_SUBTREE_value(list, i)->base;
    const ASN1_STRING* value = name->type == GEN_DNS ? name->d.dNSName : name->d.iPAddress;
    out.emplace_back(name->type, std::string(reinterpret_cast<const char*>(ASN1_STRING_get0_data(value)),
                                             static_cast<std::size_t>(ASN1_STRING_length(value))));
  }
  NAME_CONSTRAINTS_free(nc);
  return out;
}

TEST(SetupCa, CaHasCriticalNameConstraintsForClaudeAndAnthropic) {
  const EphemeralCa ca = generateConstrainedCa(testSpec());
  EXPECT_TRUE(isCritical(*ca.cert, NID_name_constraints));
  const std::vector<std::pair<int, std::string>> expected{{GEN_DNS, "claude.ai"}, {GEN_DNS, "anthropic.com"}};
  EXPECT_EQ(subtrees(*ca.cert, true), expected);
}

TEST(SetupCa, CaExcludesAllIpAddresses) {
  const EphemeralCa ca = generateConstrainedCa(testSpec());
  // An excluded iPAddress subtree is address followed by mask; all zeros means every address.
  const std::vector<std::pair<int, std::string>> expected{{GEN_IPADD, std::string(8, '\0')},
                                                          {GEN_IPADD, std::string(32, '\0')}};
  EXPECT_EQ(subtrees(*ca.cert, false), expected);
}

TEST(SetupCa, CaIsPathLenZero) {
  const EphemeralCa ca = generateConstrainedCa(testSpec());
  X509* cert = ca.cert.get();
  EXPECT_TRUE(isCritical(*cert, NID_basic_constraints));
  EXPECT_NE(X509_get_extension_flags(cert) & EXFLAG_CA, 0u);
  EXPECT_EQ(X509_get_pathlen(cert), 0);
}

TEST(SetupCa, CaKeyUsageIsOnlyCertAndCrlSigning) {
  const EphemeralCa ca = generateConstrainedCa(testSpec());
  EXPECT_TRUE(isCritical(*ca.cert, NID_key_usage));
  EXPECT_EQ(X509_get_key_usage(ca.cert.get()), static_cast<std::uint32_t>(KU_KEY_CERT_SIGN | KU_CRL_SIGN));
}

TEST(SetupCa, CaIsSelfSignedWithTheGivenName) {
  const EphemeralCa ca = generateConstrainedCa(testSpec());
  EXPECT_EQ(X509_verify(ca.cert.get(), ca.key.get()), 1);
  EXPECT_EQ(X509_NAME_cmp(X509_get_subject_name(ca.cert.get()), X509_get_issuer_name(ca.cert.get())), 0);
  char cn[128] = {};
  ASSERT_GT(X509_NAME_get_text_by_NID(X509_get_subject_name(ca.cert.get()), NID_commonName, cn, sizeof cn), 0);
  EXPECT_STREQ(cn, "llm-firewall local CA (test)");
  EXPECT_NE(X509_get0_subject_key_id(ca.cert.get()), nullptr);
}

TEST(SetupCa, CaKeyIsP256) {
  const EphemeralCa ca = generateConstrainedCa(testSpec());
  EXPECT_TRUE(EVP_PKEY_is_a(ca.key.get(), "EC"));
  char group[32] = {};
  ASSERT_EQ(EVP_PKEY_get_group_name(ca.key.get(), group, sizeof group, nullptr), 1);
  EXPECT_STREQ(group, "prime256v1");
}

TEST(SetupCa, CaValidityMatchesSpec) {
  CaSpec spec = testSpec();
  spec.validity = std::chrono::days{30};
  const EphemeralCa ca = generateConstrainedCa(spec);
  int days = 0;
  int seconds = 0;
  ASSERT_EQ(ASN1_TIME_diff(&days, &seconds, X509_get0_notBefore(ca.cert.get()), X509_get0_notAfter(ca.cert.get())), 1);
  EXPECT_EQ(days, 30);
  EXPECT_EQ(seconds, 0);
  EXPECT_LE(X509_cmp_current_time(X509_get0_notBefore(ca.cert.get())), 0);
}

TEST(SetupCa, EachCaHasADifferentPositiveSerial) {
  const EphemeralCa a = generateConstrainedCa(testSpec());
  const EphemeralCa b = generateConstrainedCa(testSpec());
  const ASN1_INTEGER* sa = X509_get0_serialNumber(a.cert.get());
  EXPECT_NE(ASN1_INTEGER_cmp(sa, X509_get0_serialNumber(b.cert.get())), 0);
  EXPECT_EQ(ASN1_STRING_type(sa), V_ASN1_INTEGER);  // V_ASN1_NEG_INTEGER would mean negative.
}

TEST(SetupCa, RejectsInvalidSpecs) {
  CaSpec no_name = testSpec();
  no_name.common_name.clear();
  EXPECT_THROW((void)generateConstrainedCa(no_name), std::invalid_argument);

  for (const std::vector<std::string>& dns : std::vector<std::vector<std::string>>{
           {}, {"*.claude.ai"}, {"claude.ai,permitted;DNS:com"}, {"Claude.AI"}, {"ai"}, {"10.0.0.1"}}) {
    CaSpec spec = testSpec();
    spec.permitted_dns = dns;
    EXPECT_THROW((void)generateConstrainedCa(spec), std::invalid_argument) << (dns.empty() ? "<empty>" : dns[0]);
  }

  CaSpec zero = testSpec();
  zero.validity = std::chrono::days{0};
  EXPECT_THROW((void)generateConstrainedCa(zero), std::invalid_argument);
}

TEST(SetupCa, DestroyCaKeyNullsKeyAndKeepsCert) {
  EphemeralCa ca = generateConstrainedCa(testSpec());
  destroyCaKey(ca);
  EXPECT_EQ(ca.key, nullptr);
  EXPECT_NE(ca.cert, nullptr);
  destroyCaKey(ca);  // Idempotent.
  EXPECT_EQ(ca.key, nullptr);
}

TEST(SetupCa, CaPemContainsNoPrivateKey) {
  const EphemeralCa ca = generateConstrainedCa(testSpec());
  const std::string pem = caCertificatePem(ca);
  EXPECT_EQ(pem.rfind("-----BEGIN CERTIFICATE-----\n", 0), 0u);
  EXPECT_EQ(pem.find("PRIVATE KEY"), std::string::npos);
  EXPECT_EQ(pem.find("-----BEGIN", 1), std::string::npos);  // Exactly one PEM block.
}

TEST(SetupCa, CaPemRoundTrips) {
  const EphemeralCa ca = generateConstrainedCa(testSpec());
  const std::string pem = caCertificatePem(ca);
  const BioPtr bio(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())));
  const X509Ptr parsed(PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr));
  ASSERT_NE(parsed, nullptr);
  EXPECT_EQ(X509_cmp(parsed.get(), ca.cert.get()), 0);
}

TEST(SetupCa, CaPemRequiresACertificate) {
  EXPECT_THROW((void)caCertificatePem(EphemeralCa{}), std::invalid_argument);
}

TEST(SetupCa, FingerprintIsLowerHexSha256OfDer) {
  const EphemeralCa ca = generateConstrainedCa(testSpec());
  unsigned char* der = nullptr;
  const int der_len = i2d_X509(ca.cert.get(), &der);
  ASSERT_GT(der_len, 0);
  unsigned char digest[32];
  unsigned int digest_len = 0;
  ASSERT_EQ(EVP_Digest(der, static_cast<std::size_t>(der_len), digest, &digest_len, EVP_sha256(), nullptr), 1);
  OPENSSL_free(der);
  std::string expected;
  for (unsigned int i = 0; i < digest_len; ++i) {
    static constexpr char kHex[] = "0123456789abcdef";
    expected += kHex[digest[i] >> 4];
    expected += kHex[digest[i] & 0x0f];
  }
  EXPECT_EQ(sha256Fingerprint(*ca.cert), expected);
  EXPECT_EQ(expected.size(), 64u);
}

TEST(SetupCa, CommonNameNamesTheMachineAndDate) {
  using namespace std::chrono;
  const sys_days day = year{2026} / October / 7;
  EXPECT_EQ(caCommonName("arnavs-mac.local", day), "llm-firewall local CA (arnavs-mac 2026-10-07)");
  EXPECT_EQ(caCommonName("build-host", day), "llm-firewall local CA (build-host 2026-10-07)");
  EXPECT_TRUE(caCommonName("h", day).starts_with(kCaCommonNamePrefix));
}

/// A certificate whose issuer is its own subject, with the given CN and extensions
/// (nid, OpenSSL config value), signed by its own key or by `signer` if given.
X509Ptr handMadeCa(const std::string& cn, const std::vector<std::pair<int, std::string>>& extensions,
                   EVP_PKEY* signer = nullptr) {
  const EvpPkeyPtr key(EVP_EC_gen("P-256"));
  X509Ptr cert(X509_new());
  X509_set_version(cert.get(), X509_VERSION_3);
  setRandomSerial(*cert);
  setValidity(*cert, std::chrono::days{30});
  X509_NAME* name = X509_get_subject_name(cert.get());
  X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_UTF8, reinterpret_cast<const unsigned char*>(cn.c_str()), -1, -1,
                             0);
  X509_set_issuer_name(cert.get(), name);
  X509_set_pubkey(cert.get(), key.get());
  for (const auto& [nid, value] : extensions) {
    addExtension(*cert, *cert, nid, value);
  }
  X509_sign(cert.get(), signer != nullptr ? signer : key.get(), EVP_sha256());
  return cert;
}

const std::pair<int, std::string> kCaBasics{NID_basic_constraints, "critical,CA:TRUE,pathlen:0"};
const std::pair<int, std::string> kOurConstraints{
    NID_name_constraints,
    "critical,permitted;DNS:claude.ai,permitted;DNS:anthropic.com,excluded;IP:0.0.0.0/0.0.0.0,excluded;IP:::/::"};

TEST(SetupCa, TrustableCaAcceptsGeneratedCa) {
  EphemeralCa ca = generateConstrainedCa(testSpec());
  destroyCaKey(ca);
  EXPECT_NO_THROW(checkTrustableCa(*ca.cert));
  EXPECT_NO_THROW(checkTrustableCa(*handMadeCa("llm-firewall local CA (hand)", {kCaBasics, kOurConstraints})));
}

TEST(SetupCa, TrustableCaRejectsOtherNames) {
  EXPECT_THROW(checkTrustableCa(*handMadeCa("Some other CA", {kCaBasics, kOurConstraints})), std::invalid_argument);
}

TEST(SetupCa, TrustableCaRejectsMissingOrWeakerNameConstraints) {
  const std::string cn = "llm-firewall local CA (hand)";
  const std::vector<std::vector<std::pair<int, std::string>>> weaker{
      {kCaBasics},
      {kCaBasics, {NID_name_constraints, "permitted;DNS:claude.ai,permitted;DNS:anthropic.com,"
                                         "excluded;IP:0.0.0.0/0.0.0.0,excluded;IP:::/::"}},
      {kCaBasics, {NID_name_constraints, "critical,permitted;DNS:claude.ai,permitted;DNS:anthropic.com"}},
      {kCaBasics, {NID_name_constraints, "critical,permitted;DNS:claude.ai,permitted;DNS:anthropic.com,"
                                         "excluded;IP:0.0.0.0/0.0.0.0"}},
      {kCaBasics, {NID_name_constraints, "critical,permitted;DNS:claude.ai,permitted;DNS:anthropic.com,"
                                         "permitted;DNS:example.com,excluded;IP:0.0.0.0/0.0.0.0,excluded;IP:::/::"}},
      {kCaBasics, {NID_name_constraints, "critical,permitted;DNS:claude.ai,"
                                         "excluded;IP:0.0.0.0/0.0.0.0,excluded;IP:::/::"}},
      {kCaBasics, {NID_name_constraints, "critical,permitted;DNS:claude.ai,permitted;DNS:anthropic.com,"
                                         "permitted;IP:10.0.0.0/255.0.0.0,excluded;IP:0.0.0.0/0.0.0.0,excluded;IP:::/::"}},
  };
  for (std::size_t i = 0; i < weaker.size(); ++i) {
    EXPECT_THROW(checkTrustableCa(*handMadeCa(cn, weaker[i])), std::invalid_argument) << "case " << i;
  }
}

TEST(SetupCa, TrustableCaRejectsWrongBasicConstraints) {
  const std::string cn = "llm-firewall local CA (hand)";
  for (const std::string& basics : {"critical,CA:TRUE", "CA:TRUE,pathlen:0", "critical,CA:TRUE,pathlen:1",
                                    "critical,CA:FALSE"}) {
    EXPECT_THROW(checkTrustableCa(*handMadeCa(cn, {{NID_basic_constraints, basics}, kOurConstraints})),
                 std::invalid_argument)
        << basics;
  }
  EXPECT_THROW(checkTrustableCa(*handMadeCa(cn, {kOurConstraints})), std::invalid_argument);
}

TEST(SetupCa, TrustableCaRejectsCertificatesNotSelfSigned) {
  const EphemeralCa ca = generateConstrainedCa(testSpec());
  EXPECT_THROW(checkTrustableCa(*handMadeCa("llm-firewall local CA (hand)", {kCaBasics, kOurConstraints},
                                            ca.key.get())),
               std::invalid_argument);
  const IssuedLeaf leaf = issueLeaf(ca, LeafSpec{});
  EXPECT_THROW(checkTrustableCa(*leaf.cert), std::invalid_argument);
}

}  // namespace
}  // namespace llmfw::setup
