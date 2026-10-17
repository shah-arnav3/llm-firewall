#pragma once
// Local CA generation with X.509 Name Constraints. The CA private key lives only
// in memory and is destroyed right after the leaf certificate is signed. It is
// never serialized.

#include <chrono>
#include <string>
#include <string_view>
#include <vector>

#include "llmfw/openssl_ptr.hpp"

namespace llmfw::setup {

struct CaSpec {
  /// Subject CN. It includes the host name and creation date so the Keychain entry is recognizable.
  std::string common_name;
  /// Name Constraints permittedSubtrees (dNSName). Per RFC 5280, "claude.ai" permits
  /// claude.ai and every subdomain.
  std::vector<std::string> permitted_dns{"claude.ai", "anthropic.com"};
  std::chrono::days validity{400};
};

/// A CA whose key has not been destroyed yet. It exists only inside the setup CLI.
struct EphemeralCa {
  /// Self-signed, valid from now for spec.validity, with a random 128-bit serial.
  /// basicConstraints critical CA:TRUE, pathlen:0. keyUsage critical keyCertSign, cRLSign.
  /// nameConstraints critical: permitted dNSName = spec.permitted_dns, excluded
  /// iPAddress 0.0.0.0/0 and ::/0, so the CA can never vouch for an IP address.
  X509Ptr cert;
  EvpPkeyPtr key;  ///< ECDSA P-256. Never written anywhere.
};

/// Generates the key pair and the self-signed, name-constrained certificate.
/// @throws std::invalid_argument if common_name is empty, permitted_dns is empty,
///         an entry is not a normalized host name of at least two labels (see
///         HostScope::isValidPattern; wildcards are not allowed), or validity is not positive.
/// @throws std::runtime_error on any OpenSSL failure.
[[nodiscard]] EphemeralCa generateConstrainedCa(const CaSpec& spec);

/// Frees the private key (EVP_PKEY_free wipes the key material) and leaves ca.key
/// null. After this call nothing can sign with this CA again. The certificate is kept.
void destroyCaKey(EphemeralCa& ca) noexcept;

/// Every llm-firewall CA's common name starts with this, so its Keychain entries can be found.
inline constexpr std::string_view kCaCommonNamePrefix = "llm-firewall local CA";

/// "llm-firewall local CA (<host> <YYYY-MM-DD>)", where host is the machine name
/// without a trailing ".local". Distinguishes CAs made on different machines or days.
[[nodiscard]] std::string caCommonName(std::string_view host, std::chrono::sys_days created);

/// PEM of the certificate only, never the key. Used for <certs>/ca.pem and Keychain import.
/// @throws std::invalid_argument if ca.cert is null. @throws std::runtime_error on an OpenSSL failure.
[[nodiscard]] std::string caCertificatePem(const EphemeralCa& ca);

/// Lower-case hex SHA-256 of the DER certificate (64 characters). Identifies the CA
/// in the Keychain for uninstall. @throws std::runtime_error on an OpenSSL failure.
[[nodiscard]] std::string sha256Fingerprint(const X509& cert);

}  // namespace llmfw::setup
