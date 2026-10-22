#pragma once
// Trust and untrust of the local CA in the user's Keychain.

#include <filesystem>
#include <string>
#include <vector>

namespace llmfw::setup {

struct InstalledCa {
  std::string sha256_fingerprint;  ///< Lower-case hex of the DER certificate.
  std::string common_name;
  bool trusted = false;  ///< Has trust settings in the user domain.
};

/// Changes go through Apple's `security` tool: macOS refuses trust-settings changes
/// made through the Security API from this binary (errSecInternalComponent), but
/// accepts them from the Apple-signed tool. Trust is set in the USER trust-settings
/// domain only, never the admin or system domain. macOS asks the user to confirm each
/// change, which is expected and not bypassed. Nothing here needs sudo.
class KeychainTrust {
 public:
  /// @param security_tool the `security` executable to run; tests pass a fake one.
  explicit KeychainTrust(std::filesystem::path security_tool = "/usr/bin/security");

  /// Runs `security add-trusted-cert -r trustRoot -p ssl <file>`: adds the certificate
  /// to the default (login) keychain and trusts it as a root for the SSL policy only.
  /// Does not check what the certificate is: run checkTrustableCa first.
  /// @throws std::invalid_argument if the file does not hold a PEM certificate.
  /// @throws std::runtime_error if the tool fails, including when the user cancels.
  void trustCa(const std::filesystem::path& certificate_file);

  /// Runs `security delete-certificate -Z <sha1> -t` for every keychain copy of the
  /// certificate whose SHA-256 fingerprint matches, which deletes the certificate and
  /// its user trust settings. Returns false if no such certificate exists, which is
  /// not an error during uninstall.
  /// @throws std::invalid_argument if the fingerprint is not 64 lower-case hex digits.
  /// @throws std::runtime_error if the tool fails, including when the user cancels.
  bool untrustCa(const std::string& sha256_fingerprint);

  /// Certificates in the user's keychain search list whose CN starts with
  /// kCaCommonNamePrefix, one entry per fingerprint. Read-only: it never prompts.
  /// @throws std::runtime_error on a Security error.
  [[nodiscard]] std::vector<InstalledCa> findInstalled() const;

 private:
  std::filesystem::path security_tool_;
};

}  // namespace llmfw::setup
