#include "llmfw/setup_x509.hpp"

#include <array>

#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>

#include "llmfw/openssl_ptr.hpp"

namespace llmfw::setup {

void setRandomSerial(X509& cert) {
  std::array<unsigned char, 16> bytes{};
  if (RAND_bytes(bytes.data(), static_cast<int>(bytes.size())) != 1) {
    throwOpenSslError("generate certificate serial");
  }
  // Clearing the top bit keeps the serial positive; setting a low bit keeps it non-zero.
  bytes[0] = static_cast<unsigned char>((bytes[0] & 0x7f) | 0x01);
  BIGNUM* bn = BN_bin2bn(bytes.data(), static_cast<int>(bytes.size()), nullptr);
  const bool ok = bn != nullptr && BN_to_ASN1_INTEGER(bn, X509_get_serialNumber(&cert)) != nullptr;
  BN_free(bn);
  if (!ok) {
    throwOpenSslError("set certificate serial");
  }
}

void setValidity(X509& cert, std::chrono::days validity) {
  if (X509_gmtime_adj(X509_getm_notBefore(&cert), 0) == nullptr ||
      X509_time_adj_ex(X509_getm_notAfter(&cert), static_cast<int>(validity.count()), 0, nullptr) == nullptr) {
    throwOpenSslError("set certificate validity");
  }
}

void addExtension(X509& cert, X509& issuer, int nid, const std::string& value) {
  X509V3_CTX ctx;
  X509V3_set_ctx_nodb(&ctx);
  X509V3_set_ctx(&ctx, &issuer, &cert, nullptr, nullptr, 0);
  X509_EXTENSION* ext = X509V3_EXT_nconf_nid(nullptr, &ctx, nid, value.c_str());
  if (ext == nullptr) {
    throwOpenSslError("build certificate extension " + std::string(OBJ_nid2sn(nid)));
  }
  const int added = X509_add_ext(&cert, ext, -1);
  X509_EXTENSION_free(ext);
  if (added != 1) {
    throwOpenSslError("add certificate extension");
  }
}

}  // namespace llmfw::setup
