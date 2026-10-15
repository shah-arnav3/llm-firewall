#include "llmfw/setup_leaf.hpp"

#include <stdexcept>
#include <string>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

#include <sys/stat.h>
#include <unistd.h>

#include "llmfw/fs_util.hpp"
#include "llmfw/host_scope.hpp"
#include "llmfw/setup_x509.hpp"

namespace llmfw::setup {

namespace {

constexpr std::chrono::days kMaxValidity{397};
constexpr mode_t kCertMode = 0644;
constexpr mode_t kKeyMode = 0600;

void validate(const EphemeralCa& ca, const LeafSpec& spec) {
  if (!ca.cert || !ca.key) {
    throw std::invalid_argument("the CA key has been destroyed; issue the leaf before destroyCaKey");
  }
  if (spec.dns_sans.empty()) {
    throw std::invalid_argument("leaf has no DNS names");
  }
  for (const std::string& name : spec.dns_sans) {
    // The names are pasted into an OpenSSL extension string, so only host names and
    // "*.name" wildcards are accepted.
    if (!HostScope::isValidPattern(name)) {
      throw std::invalid_argument("invalid DNS name for the leaf: " + name);
    }
  }
  if (spec.validity.count() <= 0 || spec.validity > kMaxValidity) {
    throw std::invalid_argument("leaf validity must be 1 to 397 days");
  }
}

std::string subjectAltNameValue(const std::vector<std::string>& dns_sans) {
  std::string value;
  for (const std::string& name : dns_sans) {
    value += (value.empty() ? "DNS:" : ",DNS:") + name;
  }
  return value;
}

/// Chain-verifies the leaf with the CA as the only trust anchor, which also applies
/// the CA's Name Constraints to every SAN.
void verifyAgainstCa(X509& leaf, X509& ca) {
  X509_STORE* store = X509_STORE_new();
  X509_STORE_CTX* ctx = X509_STORE_CTX_new();
  const bool ready = store != nullptr && ctx != nullptr && X509_STORE_add_cert(store, &ca) == 1 &&
                     X509_STORE_CTX_init(ctx, store, &leaf, nullptr) == 1;
  const int verified = ready ? X509_verify_cert(ctx) : -1;
  const int error = ready ? X509_STORE_CTX_get_error(ctx) : X509_V_OK;
  X509_STORE_CTX_free(ctx);
  X509_STORE_free(store);
  if (!ready) {
    throwOpenSslError("set up leaf verification");
  }
  if (verified != 1) {
    throw std::runtime_error(std::string("issued leaf does not verify against the CA: ") +
                             X509_verify_cert_error_string(error));
  }
}

void requirePrivateDirectory(const std::filesystem::path& file) {
  const std::filesystem::path dir = file.parent_path().empty() ? "." : file.parent_path();
  struct stat st {};
  if (::stat(dir.c_str(), &st) != 0 || !S_ISDIR(st.st_mode) || st.st_uid != ::getuid() ||
      (st.st_mode & 07777) != 0700) {
    throw std::runtime_error(dir.string() + " must be a directory owned by you with mode 0700");
  }
}

std::string pemOf(const BioPtr& bio) {
  char* data = nullptr;
  const long size = BIO_get_mem_data(bio.get(), &data);
  return {data, static_cast<std::size_t>(size)};
}

}  // namespace

IssuedLeaf issueLeaf(const EphemeralCa& ca, const LeafSpec& spec) {
  validate(ca, spec);

  IssuedLeaf leaf;
  leaf.key.reset(EVP_EC_gen("P-256"));
  if (!leaf.key) {
    throwOpenSslError("generate leaf key");
  }
  leaf.cert.reset(X509_new());
  if (!leaf.cert) {
    throwOpenSslError("allocate leaf certificate");
  }
  X509& cert = *leaf.cert;
  X509& issuer = *ca.cert;

  if (X509_set_version(&cert, X509_VERSION_3) != 1) {
    throwOpenSslError("set leaf version");
  }
  setRandomSerial(cert);
  setValidity(cert, spec.validity);
  // Clients match the SANs, not the CN. The CN only makes the certificate recognizable.
  if (X509_NAME_add_entry_by_txt(X509_get_subject_name(&cert), "CN", MBSTRING_UTF8,
                                 reinterpret_cast<const unsigned char*>("llm-firewall proxy"), -1, -1, 0) != 1 ||
      X509_set_issuer_name(&cert, X509_get_subject_name(&issuer)) != 1) {
    throwOpenSslError("set leaf name");
  }
  if (X509_set_pubkey(&cert, leaf.key.get()) != 1) {
    throwOpenSslError("set leaf public key");
  }

  addExtension(cert, issuer, NID_basic_constraints, "critical,CA:FALSE");
  addExtension(cert, issuer, NID_key_usage, "critical,digitalSignature");
  addExtension(cert, issuer, NID_ext_key_usage, "serverAuth");
  addExtension(cert, issuer, NID_subject_key_identifier, "hash");
  addExtension(cert, issuer, NID_authority_key_identifier, "keyid:always");
  addExtension(cert, issuer, NID_subject_alt_name, subjectAltNameValue(spec.dns_sans));

  if (X509_sign(&cert, ca.key.get(), EVP_sha256()) <= 0) {
    throwOpenSslError("sign leaf certificate");
  }
  verifyAgainstCa(cert, issuer);
  return leaf;
}

void writeLeaf(const IssuedLeaf& leaf, const std::filesystem::path& cert_path,
               const std::filesystem::path& key_path) {
  requirePrivateDirectory(cert_path);
  requirePrivateDirectory(key_path);

  // A secure-memory BIO is wiped when freed, so the encoded key does not linger on the heap.
  const BioPtr key_bio(BIO_new(BIO_s_secmem()));
  if (!key_bio ||
      PEM_write_bio_PrivateKey(key_bio.get(), leaf.key.get(), nullptr, nullptr, 0, nullptr, nullptr) != 1) {
    throwOpenSslError("encode leaf key");
  }
  const BioPtr cert_bio(BIO_new(BIO_s_mem()));
  if (!cert_bio || PEM_write_bio_X509(cert_bio.get(), leaf.cert.get()) != 1) {
    throwOpenSslError("encode leaf certificate");
  }

  std::string key_pem = pemOf(key_bio);
  try {
    writeFileAtomically(key_path, key_pem, kKeyMode);
  } catch (...) {
    OPENSSL_cleanse(key_pem.data(), key_pem.size());
    throw;
  }
  OPENSSL_cleanse(key_pem.data(), key_pem.size());
  writeFileAtomically(cert_path, pemOf(cert_bio), kCertMode);
}

}  // namespace llmfw::setup
