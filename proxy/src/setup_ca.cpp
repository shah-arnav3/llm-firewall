#include "llmfw/setup_ca.hpp"

#include <array>
#include <stdexcept>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>

#include "llmfw/host_scope.hpp"

namespace llmfw::setup {

namespace {

void validate(const CaSpec& spec) {
  if (spec.common_name.empty()) {
    throw std::invalid_argument("CA common name is empty");
  }
  if (spec.permitted_dns.empty()) {
    throw std::invalid_argument("CA has no permitted DNS names");
  }
  for (const std::string& name : spec.permitted_dns) {
    // The names are pasted into an OpenSSL extension string, so only plain host
    // names are accepted: no commas, no wildcards, nothing that could add a subtree.
    if (name.starts_with("*.") || !HostScope::isValidPattern(name)) {
      throw std::invalid_argument("invalid permitted DNS name for the CA: " + name);
    }
  }
  if (spec.validity.count() <= 0) {
    throw std::invalid_argument("CA validity must be positive");
  }
}

void setRandomSerial(X509& cert) {
  std::array<unsigned char, 16> bytes{};
  if (RAND_bytes(bytes.data(), static_cast<int>(bytes.size())) != 1) {
    throwOpenSslError("generate CA serial");
  }
  // Clearing the top bit keeps the serial positive; setting a low bit keeps it non-zero.
  bytes[0] = static_cast<unsigned char>((bytes[0] & 0x7f) | 0x01);
  BIGNUM* bn = BN_bin2bn(bytes.data(), static_cast<int>(bytes.size()), nullptr);
  const bool ok = bn != nullptr && BN_to_ASN1_INTEGER(bn, X509_get_serialNumber(&cert)) != nullptr;
  BN_free(bn);
  if (!ok) {
    throwOpenSslError("set CA serial");
  }
}

void addExtension(X509& cert, X509V3_CTX& ctx, int nid, const std::string& value) {
  X509_EXTENSION* ext = X509V3_EXT_nconf_nid(nullptr, &ctx, nid, value.c_str());
  if (ext == nullptr) {
    throwOpenSslError("build CA extension " + std::string(OBJ_nid2sn(nid)));
  }
  const int added = X509_add_ext(&cert, ext, -1);
  X509_EXTENSION_free(ext);
  if (added != 1) {
    throwOpenSslError("add CA extension");
  }
}

std::string nameConstraintsValue(const std::vector<std::string>& permitted_dns) {
  std::string value = "critical";
  for (const std::string& name : permitted_dns) {
    value += ",permitted;DNS:" + name;
  }
  value += ",excluded;IP:0.0.0.0/0.0.0.0,excluded;IP:::/::";
  return value;
}

}  // namespace

EphemeralCa generateConstrainedCa(const CaSpec& spec) {
  validate(spec);

  EphemeralCa ca;
  ca.key.reset(EVP_EC_gen("P-256"));
  if (!ca.key) {
    throwOpenSslError("generate CA key");
  }
  ca.cert.reset(X509_new());
  if (!ca.cert) {
    throwOpenSslError("allocate CA certificate");
  }
  X509& cert = *ca.cert;

  if (X509_set_version(&cert, X509_VERSION_3) != 1) {
    throwOpenSslError("set CA version");
  }
  setRandomSerial(cert);
  if (X509_gmtime_adj(X509_getm_notBefore(&cert), 0) == nullptr ||
      X509_time_adj_ex(X509_getm_notAfter(&cert), static_cast<int>(spec.validity.count()), 0, nullptr) == nullptr) {
    throwOpenSslError("set CA validity");
  }

  X509_NAME* subject = X509_get_subject_name(&cert);
  if (X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_UTF8,
                                 reinterpret_cast<const unsigned char*>(spec.common_name.c_str()), -1, -1, 0) != 1 ||
      X509_set_issuer_name(&cert, subject) != 1) {
    throwOpenSslError("set CA name");
  }
  if (X509_set_pubkey(&cert, ca.key.get()) != 1) {
    throwOpenSslError("set CA public key");
  }

  X509V3_CTX ctx;
  X509V3_set_ctx_nodb(&ctx);
  X509V3_set_ctx(&ctx, &cert, &cert, nullptr, nullptr, 0);
  addExtension(cert, ctx, NID_basic_constraints, "critical,CA:TRUE,pathlen:0");
  addExtension(cert, ctx, NID_key_usage, "critical,keyCertSign,cRLSign");
  addExtension(cert, ctx, NID_subject_key_identifier, "hash");
  addExtension(cert, ctx, NID_authority_key_identifier, "keyid:always");
  addExtension(cert, ctx, NID_name_constraints, nameConstraintsValue(spec.permitted_dns));

  if (X509_sign(&cert, ca.key.get(), EVP_sha256()) <= 0) {
    throwOpenSslError("sign CA certificate");
  }
  return ca;
}

void destroyCaKey(EphemeralCa& ca) noexcept { ca.key.reset(); }

std::string caCertificatePem(const EphemeralCa& ca) {
  if (!ca.cert) {
    throw std::invalid_argument("CA has no certificate");
  }
  const BioPtr bio(BIO_new(BIO_s_mem()));
  if (!bio || PEM_write_bio_X509(bio.get(), ca.cert.get()) != 1) {
    throwOpenSslError("write CA PEM");
  }
  char* data = nullptr;
  const long size = BIO_get_mem_data(bio.get(), &data);
  return {data, static_cast<std::size_t>(size)};
}

std::string sha256Fingerprint(const X509& cert) {
  std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
  unsigned int length = 0;
  if (X509_digest(&cert, EVP_sha256(), digest.data(), &length) != 1) {
    throwOpenSslError("hash certificate");
  }
  static constexpr char kHex[] = "0123456789abcdef";
  std::string hex;
  hex.reserve(length * 2);
  for (unsigned int i = 0; i < length; ++i) {
    hex.push_back(kHex[digest[i] >> 4]);
    hex.push_back(kHex[digest[i] & 0x0f]);
  }
  return hex;
}

}  // namespace llmfw::setup
