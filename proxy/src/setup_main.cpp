// llmfw-setup: sets Claude up so its traffic goes through llmfw-proxy.
//
//   llmfw-setup profile [--config <path>] [--output <path>] [--scope user|system]
//       Writes a macOS configuration profile that sets only Claude's egressProxyPacUrl to
//       the proxy's PAC (http://<listen address>:<port>/proxy.pac). It does not install
//       it; installing it is the user's step in System Settings.
//   llmfw-setup certs [--config <path>] [--force]
//       Creates the name-constrained local CA and the leaf certificate in the
//       configured certs directory, then destroys the CA key. It changes nothing in
//       the Keychain. Existing certificate files are replaced only with --force.
//   llmfw-setup trust [--config <path>]
//       Checks that <certs>/ca.pem is a name-constrained llm-firewall CA, adds it to the
//       login keychain and trusts it for SSL in the user trust domain with Apple's
//       `security` tool (macOS asks to confirm), then checks that macOS trusts the leaf
//       for claude.ai.
//   llmfw-setup untrust
//       Removes the trust settings and the certificate of every llm-firewall CA in the
//       keychain (macOS asks to confirm each).
//   llmfw-setup --help | --version
//
// Exit codes: 0 ok; 1 usage; 2 preflight failed (bad config, certificates exist
// without --force, or ca.pem missing or not an llm-firewall CA); 4 other failure,
// including a cancelled macOS prompt.

#include <chrono>
#include <cstdio>
#include <exception>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include <unistd.h>

#include <openssl/pem.h>
#include <openssl/x509.h>

#include "llmfw/config.hpp"
#include "llmfw/fs_util.hpp"
#include "llmfw/openssl_ptr.hpp"
#include "llmfw/pac.hpp"
#include "llmfw/random_id.hpp"
#include "llmfw/setup_ca.hpp"
#include "llmfw/setup_keychain.hpp"
#include "llmfw/setup_leaf.hpp"
#include "llmfw/setup_paths.hpp"
#include "llmfw/setup_profile.hpp"
#include "llmfw/trust_verifier.hpp"

namespace {

enum SetupExit : int { kExitOk = 0, kExitUsage = 1, kExitPreflight = 2, kExitFailure = 4 };

constexpr std::string_view kUsage =
    "usage: llmfw-setup profile [--config <path>] [--output <path>] [--scope user|system]\n"
    "       llmfw-setup certs [--config <path>] [--force]\n"
    "       llmfw-setup trust [--config <path>]\n"
    "       llmfw-setup untrust\n"
    "       llmfw-setup --help | --version\n";

int usage() {
  std::fputs(kUsage.data(), stderr);
  return kExitUsage;
}

void error(const std::string& message) { std::fprintf(stderr, "llmfw-setup: %s\n", message.c_str()); }

int profile(int argc, char** argv) {
  namespace setup = llmfw::setup;
  const setup::InstallPaths paths = setup::InstallPaths::forCurrentUser();
  std::optional<std::filesystem::path> config_path;
  std::filesystem::path output = paths.profile_file;
  setup::ProfileScope scope = setup::ProfileScope::kUser;
  for (int i = 2; i < argc; ++i) {
    const std::string_view arg = argv[i];
    if (arg == "--config" && i + 1 < argc) {
      config_path = argv[++i];
    } else if (arg == "--output" && i + 1 < argc) {
      output = argv[++i];
    } else if (arg == "--scope" && i + 1 < argc && (std::string_view(argv[i + 1]) == "user" ||
                                                     std::string_view(argv[i + 1]) == "system")) {
      scope = std::string_view(argv[++i]) == "user" ? setup::ProfileScope::kUser : setup::ProfileScope::kSystem;
    } else {
      return usage();
    }
  }

  llmfw::ProxyConfig config;
  try {
    config = llmfw::loadProxyConfig(config_path ? *config_path : paths.config_file);
  } catch (const llmfw::ConfigError& e) {
    error(std::string("configuration: ") + e.what());
    return kExitPreflight;
  }

  const std::string pac_url = llmfw::pacUrl(config.listen.address, config.listen.port);
  setup::writeProfile(output,
                      setup::buildEgressProxyProfile(pac_url, scope, llmfw::randomUuid(), llmfw::randomUuid()));
  std::printf("Wrote %s\n", output.c_str());
  std::printf("It sets only Claude's egressProxyPacUrl to %s.\n\n", pac_url.c_str());
  std::printf("To install: open \"%s\", then approve it in System Settings > General > Device Management.\n",
              output.c_str());
  std::puts("Then quit Claude (Cmd-Q) and start it normally: Claude reads the setting at launch.");
  std::puts("To remove: System Settings > General > Device Management, select the profile, click Remove.");
  return kExitOk;
}

std::string hostName() {
  char name[256] = {};
  return ::gethostname(name, sizeof name - 1) == 0 && name[0] != '\0' ? name : "unknown-host";
}

int certs(int argc, char** argv) {
  namespace setup = llmfw::setup;
  namespace fs = std::filesystem;
  const setup::InstallPaths paths = setup::InstallPaths::forCurrentUser();
  std::optional<fs::path> config_path;
  bool force = false;
  for (int i = 2; i < argc; ++i) {
    const std::string_view arg = argv[i];
    if (arg == "--config" && i + 1 < argc) {
      config_path = argv[++i];
    } else if (arg == "--force") {
      force = true;
    } else {
      return usage();
    }
  }

  llmfw::ProxyConfig config;
  try {
    config = llmfw::loadProxyConfig(config_path ? *config_path : paths.config_file);
  } catch (const llmfw::ConfigError& e) {
    error(std::string("configuration: ") + e.what());
    return kExitPreflight;
  }
  const fs::path dir = config.certs.dir;
  const fs::path ca_path = dir / config.certs.ca_cert_file;
  const fs::path leaf_path = dir / config.certs.leaf_cert_file;
  const fs::path key_path = dir / config.certs.leaf_key_file;
  if (!force) {
    for (const fs::path& path : {ca_path, leaf_path, key_path}) {
      if (fs::exists(fs::symlink_status(path))) {
        error(path.string() + " already exists; run with --force to replace the certificates");
        return kExitPreflight;
      }
    }
  }

  llmfw::createPrivateDirectories(dir);
  setup::CaSpec ca_spec;
  ca_spec.common_name =
      setup::caCommonName(hostName(), std::chrono::floor<std::chrono::days>(std::chrono::system_clock::now()));
  setup::EphemeralCa ca = setup::generateConstrainedCa(ca_spec);
  const setup::IssuedLeaf leaf = setup::issueLeaf(ca, setup::LeafSpec{});
  setup::destroyCaKey(ca);

  setup::writeLeaf(leaf, leaf_path, key_path);
  llmfw::writeFileAtomically(ca_path, setup::caCertificatePem(ca), 0644);

  std::printf("Created %s\n", ca_spec.common_name.c_str());
  std::printf("  CA certificate: %s\n", ca_path.c_str());
  std::printf("  SHA-256 fingerprint: %s\n", setup::sha256Fingerprint(*ca.cert).c_str());
  std::printf("  Leaf certificate: %s\n", leaf_path.c_str());
  std::printf("  Leaf key: %s\n", key_path.c_str());
  std::puts("The CA key was destroyed: nothing can issue new certificates from this CA.");
  std::puts("Nothing in your Keychain changed, so no client trusts this CA yet.");
  return kExitOk;
}

/// The certificate in a PEM file, or null if the file cannot be read or holds none.
llmfw::X509Ptr readPemCertificate(const std::filesystem::path& path) {
  const llmfw::BioPtr bio(BIO_new_file(path.c_str(), "r"));
  return llmfw::X509Ptr(bio ? PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr) : nullptr);
}

int trust(int argc, char** argv) {
  namespace setup = llmfw::setup;
  namespace fs = std::filesystem;
  const setup::InstallPaths paths = setup::InstallPaths::forCurrentUser();
  std::optional<fs::path> config_path;
  for (int i = 2; i < argc; ++i) {
    if (std::string_view(argv[i]) == "--config" && i + 1 < argc) {
      config_path = argv[++i];
    } else {
      return usage();
    }
  }

  llmfw::ProxyConfig config;
  try {
    config = llmfw::loadProxyConfig(config_path ? *config_path : paths.config_file);
  } catch (const llmfw::ConfigError& e) {
    error(std::string("configuration: ") + e.what());
    return kExitPreflight;
  }
  const fs::path ca_path = config.certs.dir / config.certs.ca_cert_file;
  const fs::path leaf_path = config.certs.dir / config.certs.leaf_cert_file;
  const llmfw::X509Ptr ca = readPemCertificate(ca_path);
  const llmfw::X509Ptr leaf = readPemCertificate(leaf_path);
  if (!ca || !leaf) {
    error("cannot read " + (ca ? leaf_path : ca_path).string() + "; run llmfw-setup certs first");
    return kExitPreflight;
  }
  try {
    setup::checkTrustableCa(*ca);
  } catch (const std::invalid_argument& e) {
    error(ca_path.string() + " will not be trusted: " + e.what());
    return kExitPreflight;
  }

  const std::string fingerprint = setup::sha256Fingerprint(*ca);
  setup::KeychainTrust keychain;
  std::puts("macOS will ask you to confirm the trust change.");
  keychain.trustCa(ca_path);
  std::printf("Trusted %s for SSL in your login keychain.\n", ca_path.c_str());
  std::printf("  SHA-256 fingerprint: %s\n", fingerprint.c_str());

  // The macOS trust evaluation the proxy uses for origins, given the leaf and the
  // CA as a TLS client would see them: it succeeds only if the CA's trust is in effect.
  // macOS does not look up the issuer in the keychain, so the CA must be in the chain.
  STACK_OF(X509)* chain = sk_X509_new_null();
  sk_X509_push(chain, leaf.get());
  sk_X509_push(chain, ca.get());
  const llmfw::VerifyResult verdict = llmfw::SystemTrustVerifier().verify(chain, "claude.ai");
  sk_X509_free(chain);
  if (!verdict.ok) {
    error("macOS still does not trust " + leaf_path.string() + " for claude.ai: " + verdict.reason);
    return kExitFailure;
  }
  std::puts("macOS now trusts the leaf certificate for claude.ai.");

  for (const setup::InstalledCa& other : keychain.findInstalled()) {
    if (other.sha256_fingerprint != fingerprint) {
      std::printf("Another llm-firewall CA is still in the keychain: %s (%s)\n", other.common_name.c_str(),
                  other.sha256_fingerprint.c_str());
    }
  }
  std::puts("To undo: llmfw-setup untrust");
  return kExitOk;
}

int untrust(int argc, char** /*argv*/) {
  if (argc != 2) {
    return usage();
  }
  llmfw::setup::KeychainTrust keychain;
  const std::vector<llmfw::setup::InstalledCa> installed = keychain.findInstalled();
  if (installed.empty()) {
    std::puts("No llm-firewall CA is in the keychain.");
    return kExitOk;
  }
  std::puts("macOS will ask you to confirm each trust change.");
  for (const llmfw::setup::InstalledCa& ca : installed) {
    keychain.untrustCa(ca.sha256_fingerprint);
    std::printf("Removed %s (%s)\n", ca.common_name.c_str(), ca.sha256_fingerprint.c_str());
  }
  return kExitOk;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc < 2) {
    return usage();
  }
  const std::string_view command = argv[1];
  if (command == "--help" || command == "-h") {
    std::fputs(kUsage.data(), stdout);
    return kExitOk;
  }
  if (command == "--version") {
    std::puts("llmfw-setup " LLMFW_VERSION);
    return kExitOk;
  }
  try {
    if (command == "profile") {
      return profile(argc, argv);
    }
    if (command == "certs") {
      return certs(argc, argv);
    }
    if (command == "trust") {
      return trust(argc, argv);
    }
    if (command == "untrust") {
      return untrust(argc, argv);
    }
    return usage();
  } catch (const std::exception& e) {
    error(e.what());
    return kExitFailure;
  }
}
