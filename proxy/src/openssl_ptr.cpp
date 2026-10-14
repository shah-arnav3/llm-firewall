#include "llmfw/openssl_ptr.hpp"

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

namespace llmfw {

void OpenSslDeleter::operator()(X509* p) const noexcept { X509_free(p); }
void OpenSslDeleter::operator()(EVP_PKEY* p) const noexcept { EVP_PKEY_free(p); }
// BIO_free_all also frees any BIOs chained after this one (for example a base64 filter).
void OpenSslDeleter::operator()(BIO* p) const noexcept { BIO_free_all(p); }

}  // namespace llmfw
