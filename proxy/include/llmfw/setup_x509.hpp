#pragma once
// Certificate-building steps shared by the CA and leaf issuers.

#include <chrono>
#include <string>

#include <openssl/types.h>

namespace llmfw::setup {

/// Sets a random, positive, non-zero 128-bit serial. @throws std::runtime_error on an OpenSSL failure.
void setRandomSerial(X509& cert);

/// Sets notBefore to now and notAfter to now + validity. @throws std::runtime_error on an OpenSSL failure.
void setValidity(X509& cert, std::chrono::days validity);

/// Builds the extension from OpenSSL's config syntax (for example "critical,CA:TRUE")
/// and appends it. `issuer` is the certificate whose key will sign `cert`, and is
/// used for authorityKeyIdentifier. @throws std::runtime_error on an OpenSSL failure.
void addExtension(X509& cert, X509& issuer, int nid, const std::string& value);

}  // namespace llmfw::setup
