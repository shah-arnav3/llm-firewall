#pragma once
// Issues the leaf certificate the proxy presents to clients for scoped hosts.

#include <chrono>
#include <filesystem>
#include <string>
#include <vector>

#include "llmfw/openssl_ptr.hpp"
#include "llmfw/setup_ca.hpp"

namespace llmfw::setup {

struct LeafSpec {
  /// dNSName SANs, as host names or "*.name" wildcards. They must all be inside the
  /// CA's permitted subtrees.
  std::vector<std::string> dns_sans{"claude.ai", "*.claude.ai", "anthropic.com", "*.anthropic.com"};
  /// At most 397 days. User-trusted anchors are exempt from the public-CA limits,
  /// but staying under them keeps every client happy. Renewal is yearly.
  std::chrono::days validity{397};
};

struct IssuedLeaf {
  /// Signed by the CA, valid from now for spec.validity, with a random 128-bit serial.
  /// basicConstraints critical CA:FALSE. keyUsage critical digitalSignature.
  /// extendedKeyUsage serverAuth. subjectAltName = spec.dns_sans.
  X509Ptr cert;
  EvpPkeyPtr key;  ///< ECDSA P-256.
};

/// Signs a fresh leaf with the ephemeral CA, then verifies it against the CA
/// (including Name Constraints) before returning it.
/// @throws std::invalid_argument if the CA key was already destroyed, dns_sans is
///         empty or holds an invalid name (see HostScope::isValidPattern), or validity
///         is not in 1..397 days.
/// @throws std::runtime_error on an OpenSSL failure, or if the leaf does not verify
///         against the CA (for example, a SAN outside its permitted subtrees).
[[nodiscard]] IssuedLeaf issueLeaf(const EphemeralCa& ca, const LeafSpec& spec);

/// Writes the key (mode 0600, unencrypted PKCS#8 PEM) and then the certificate
/// (mode 0644, PEM), each atomically: readers see the old file or the new one, never
/// a partial one. If the certificate write fails after the key was replaced, the
/// pair no longer matches; the proxy's certificate store detects that when loading.
/// @throws std::runtime_error if a parent directory is not owned by the current user
///         with mode 0700, or on an OpenSSL failure.
/// @throws std::system_error if a file cannot be written.
void writeLeaf(const IssuedLeaf& leaf, const std::filesystem::path& cert_path,
               const std::filesystem::path& key_path);

}  // namespace llmfw::setup
