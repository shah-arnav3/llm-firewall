#pragma once
// Strict verification of upstream (origin) certificate chains with macOS trust evaluation.

#include <filesystem>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include <openssl/x509.h>

#include "llmfw/config.hpp"

namespace llmfw {

struct VerifyResult {
  bool ok = false;
  std::string reason;  ///< Why verification failed, for operational logs. Never contains content.
};

/// Decides whether an origin's certificate chain is trusted for a host name. There
/// is no "allow insecure" mode: a failure is always final for decryption, and the
/// connection is blind-tunneled instead.
///
/// verify() runs SecTrustEvaluateWithError, which may block on the network (revocation
/// checks, fetching missing intermediates). Call it off the I/O threads.
class UpstreamTrustVerifier {
 public:
  virtual ~UpstreamTrustVerifier() = default;

  /// @param chain    the peer chain as presented, leaf first. Not modified.
  /// @param hostname the CONNECT host (normalized). The chain must be valid for it.
  [[nodiscard]] virtual VerifyResult verify(STACK_OF(X509)* chain, std::string_view hostname) const = 0;
};

/// macOS system trust: SecTrustCreateWithCertificates + SecPolicyCreateSSL(server, hostname)
/// + SecTrustEvaluateWithError. Uses the same roots, enterprise roots, user trust
/// settings and revocation policy as other macOS apps.
class SystemTrustVerifier final : public UpstreamTrustVerifier {
 public:
  [[nodiscard]] VerifyResult verify(STACK_OF(X509)* chain, std::string_view hostname) const override;
};

/// The same evaluation, but trusting only the CA certificates in a PEM bundle and
/// never the system roots. For tests.
class PemBundleTrustVerifier final : public UpstreamTrustVerifier {
 public:
  /// @throws ConfigError if the file cannot be read or holds no certificate.
  explicit PemBundleTrustVerifier(const std::filesystem::path& bundle);
  [[nodiscard]] VerifyResult verify(STACK_OF(X509)* chain, std::string_view hostname) const override;

 private:
  std::vector<std::vector<unsigned char>> anchors_der_;
};

/// The verifier for upstream.trust. @throws ConfigError as PemBundleTrustVerifier does.
[[nodiscard]] std::shared_ptr<const UpstreamTrustVerifier> makeTrustVerifier(const UpstreamConfig& cfg);

}  // namespace llmfw
