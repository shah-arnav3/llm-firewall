#include "llmfw/setup_ca.hpp"

#include <algorithm>
#include <array>
#include <cstdio>
#include <stdexcept>
#include <utility>

#include <openssl/ec.h>
#include <openssl/err.h>
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

std::string asString(const ASN1_STRING* value) {
  return {reinterpret_cast<const char*>(ASN1_STRING_get0_data(value)), static_cast<std::size_t>(ASN1_STRING_length(value))};
}

std::string commonName(const X509& cert) {
  const X509_NAME* subject = X509_get_subject_name(&cert);
  const int index = X509_NAME_get_index_by_NID(subject, NID_commonName, -1);
  return index < 0 ? std::string() : asString(X509_NAME_ENTRY_get_data(X509_NAME_get_entry(subject, index)));
}

/// The subtrees as (type, value), where value is the DNS name or the raw IP address and mask.
std::vector<std::pair<int, std::string>> subtrees(const STACK_OF(GENERAL_SUBTREE) * list) {
  std::vector<std::pair<int, std::string>> out;
  for (int i = 0; i < sk_GENERAL_SUBTREE_num(list); ++i) {
    const GENERAL_NAME* name = sk_GENERAL_SUBTREE_value(list, i)->base;
    if (name->type == GEN_DNS) {
      out.emplace_back(GEN_DNS, asString(name->d.dNSName));
    } else if (name->type == GEN_IPADD) {
      out.emplace_back(GEN_IPADD, asString(name->d.iPAddress));
    } else {
      out.emplace_back(name->type, std::string());
    }
  }
  std::sort(out.begin(), out.end());
  return out;
}

void checkBasicConstraints(const X509& cert) {
  int critical = 0;
  auto* bc = static_cast<BASIC_CONSTRAINTS*>(X509_get_ext_d2i(&cert, NID_basic_constraints, &critical, nullptr));
  const bool ok = bc != nullptr && critical == 1 && bc->ca != 0 && bc->pathlen != nullptr &&
                  ASN1_INTEGER_get(bc->pathlen) == 0;
  BASIC_CONSTRAINTS_free(bc);
  if (!ok) {
    throw std::invalid_argument("the certificate is not a CA with critical basicConstraints pathlen:0");
  }
}

void checkNameConstraints(const X509& cert) {
  int critical = 0;
  auto* nc = static_cast<NAME_CONSTRAINTS*>(X509_get_ext_d2i(&cert, NID_name_constraints, &critical, nullptr));
  if (nc == nullptr || critical != 1) {
    NAME_CONSTRAINTS_free(nc);
    throw std::invalid_argument("the certificate has no critical Name Constraints");
  }
  const std::vector<std::pair<int, std::string>> permitted = subtrees(nc->permittedSubtrees);
  const std::vector<std::pair<int, std::string>> excluded = subtrees(nc->excludedSubtrees);
  NAME_CONSTRAINTS_free(nc);

  std::vector<std::pair<int, std::string>> expected_permitted;
  for (const std::string& name : CaSpec{}.permitted_dns) {
    expected_permitted.emplace_back(GEN_DNS, name);
  }
  std::sort(expected_permitted.begin(), expected_permitted.end());
  if (permitted != expected_permitted) {
    throw std::invalid_argument("the certificate's Name Constraints do not permit exactly claude.ai and anthropic.com");
  }
  // Address followed by mask, all zeros: every IPv4 and every IPv6 address.
  const std::vector<std::pair<int, std::string>> expected_excluded{{GEN_IPADD, std::string(8, '\0')},
                                                                   {GEN_IPADD, std::string(32, '\0')}};
  if (excluded != expected_excluded) {
    throw std::invalid_argument("the certificate's Name Constraints do not exclude every IP address");
  }
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

void checkTrustableCa(X509& cert) {
  if (!commonName(cert).starts_with(kCaCommonNamePrefix)) {
    throw std::invalid_argument("the certificate's common name does not start with \"" +
                                std::string(kCaCommonNamePrefix) + "\"");
  }
  EVP_PKEY* key = X509_get0_pubkey(&cert);
  if (X509_check_issued(&cert, &cert) != X509_V_OK || key == nullptr || X509_verify(&cert, key) != 1) {
    ERR_clear_error();
    throw std::invalid_argument("the certificate is not self-signed");
  }
  checkBasicConstraints(cert);
  checkNameConstraints(cert);
}

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
