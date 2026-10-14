#pragma once
// RAII owners for OpenSSL objects used by both the proxy and the setup CLI.

#include <memory>

#include <openssl/types.h>

namespace llmfw {

/// Calls the matching OpenSSL *_free function, and does nothing for nullptr.
/// EVP_PKEY_free wipes private-key material before freeing it, and the setup CLI
/// relies on this to destroy the CA key.
struct OpenSslDeleter {
  void operator()(X509* p) const noexcept;
  void operator()(EVP_PKEY* p) const noexcept;
  void operator()(BIO* p) const noexcept;
};

using X509Ptr = std::unique_ptr<X509, OpenSslDeleter>;
using EvpPkeyPtr = std::unique_ptr<EVP_PKEY, OpenSslDeleter>;
using BioPtr = std::unique_ptr<BIO, OpenSslDeleter>;

}  // namespace llmfw
