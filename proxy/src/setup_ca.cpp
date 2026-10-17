#include "llmfw/setup_ca.hpp"

#include <array>
#include <cstdio>
#include <stdexcept>

#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

#include "llmfw/host_scope.hpp"
#include "llmfw/setup_x509.hpp"

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
  setValidity(cert, spec.validity);

  X509_NAME* subject = X509_get_subject_name(&cert);
  if (X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_UTF8,
                                 reinterpret_cast<const unsigned char*>(spec.common_name.c_str()), -1, -1, 0) != 1 ||
      X509_set_issuer_name(&cert, subject) != 1) {
    throwOpenSslError("set CA name");
  }
  if (X509_set_pubkey(&cert, ca.key.get()) != 1) {
    throwOpenSslError("set CA public key");
  }

  addExtension(cert, cert, NID_basic_constraints, "critical,CA:TRUE,pathlen:0");
  addExtension(cert, cert, NID_key_usage, "critical,keyCertSign,cRLSign");
  addExtension(cert, cert, NID_subject_key_identifier, "hash");
  addExtension(cert, cert, NID_authority_key_identifier, "keyid:always");
  addExtension(cert, cert, NID_name_constraints, nameConstraintsValue(spec.permitted_dns));

  if (X509_sign(&cert, ca.key.get(), EVP_sha256()) <= 0) {
    throwOpenSslError("sign CA certificate");
  }
  return ca;
}

std::string caCommonName(std::string_view host, std::chrono::sys_days created) {
  if (host.ends_with(".local")) {
    host.remove_suffix(std::string_view(".local").size());
  }
  const std::chrono::year_month_day ymd{created};
  char date[16];
  std::snprintf(date, sizeof date, "%04d-%02u-%02u", static_cast<int>(ymd.year()),
                static_cast<unsigned>(ymd.month()), static_cast<unsigned>(ymd.day()));
  return std::string(kCaCommonNamePrefix) + " (" + std::string(host) + " " + date + ")";
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
