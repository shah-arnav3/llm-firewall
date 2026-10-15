#include "llmfw/openssl_ptr.hpp"

#include <stdexcept>
#include <string>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

namespace llmfw {

void OpenSslDeleter::operator()(X509* p) const noexcept { X509_free(p); }
void OpenSslDeleter::operator()(EVP_PKEY* p) const noexcept { EVP_PKEY_free(p); }
// BIO_free_all also frees any BIOs chained after this one (for example a base64 filter).
void OpenSslDeleter::operator()(BIO* p) const noexcept { BIO_free_all(p); }

void throwOpenSslError(std::string_view context) {
  const unsigned long code = ERR_get_error();
  ERR_clear_error();
  std::string reason = "unknown OpenSSL error";
  if (code != 0) {
    char buf[256];
    ERR_error_string_n(code, buf, sizeof buf);
    reason = buf;
  }
  throw std::runtime_error(std::string(context) + ": " + reason);
}

}  // namespace llmfw
