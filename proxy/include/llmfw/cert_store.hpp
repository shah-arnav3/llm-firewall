#pragma once
// The pre-issued leaf certificate used to terminate client TLS for scoped hosts.
// The store holds no CA key and cannot mint certificates. It can only serve the
// certificate llmfw-setup issued.

#include <chrono>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include "llmfw/config.hpp"
#include "llmfw/openssl_ptr.hpp"

namespace llmfw {

/// The certificate files are missing, unsafe, or unusable.
class CertStoreError : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

class LeafCertStore {
 public:
  /// Loads <dir>/<leaf_cert_file> and <dir>/<leaf_key_file>.
  /// @throws CertStoreError if:
  ///   - dir is not a directory owned by the current user with mode 0700
  ///   - either file is missing, a symlink, or not a regular file owned by the current user
  ///   - the key file's mode is not 0600
  ///   - either file does not parse, or the key does not match the certificate
  ///   - the certificate has no dNSName SAN, is not yet valid, or has expired
  [[nodiscard]] static LeafCertStore load(const CertConfig& cfg);

  /// True if a SAN covers the host under RFC 6125 matching: an exact name, or a
  /// "*.name" wildcard covering exactly one non-empty left-most label.
  [[nodiscard]] bool covers(std::string_view normalized_host) const;

  [[nodiscard]] X509& certificate() const { return *cert_; }
  [[nodiscard]] EVP_PKEY& privateKey() const { return *key_; }

  /// The certificate's notAfter. The proxy warns when it is near.
  [[nodiscard]] std::chrono::system_clock::time_point notAfter() const { return not_after_; }

  /// The dNSName SANs, lower-cased, in certificate order.
  [[nodiscard]] const std::vector<std::string>& dnsNames() const { return dns_names_; }

 private:
  LeafCertStore() = default;

  X509Ptr cert_;
  EvpPkeyPtr key_;
  std::vector<std::string> dns_names_;
  std::chrono::system_clock::time_point not_after_;
};

}  // namespace llmfw
