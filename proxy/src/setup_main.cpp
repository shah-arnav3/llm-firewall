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
//   llmfw-setup --help | --version
//
// Exit codes: 0 ok; 1 usage; 2 preflight failed (bad config, or certificates exist
// without --force); 4 other failure.

#include <chrono>
#include <cstdio>
#include <exception>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>

#include <unistd.h>

#include "llmfw/config.hpp"
#include "llmfw/fs_util.hpp"
#include "llmfw/pac.hpp"
#include "llmfw/random_id.hpp"
#include "llmfw/setup_ca.hpp"
#include "llmfw/setup_leaf.hpp"
#include "llmfw/setup_paths.hpp"
#include "llmfw/setup_profile.hpp"

namespace {

enum SetupExit : int { kExitOk = 0, kExitUsage = 1, kExitPreflight = 2, kExitFailure = 4 };

constexpr std::string_view kUsage =
    "usage: llmfw-setup profile [--config <path>] [--output <path>] [--scope user|system]\n"
    "       llmfw-setup certs [--config <path>] [--force]\n"
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
  if (command != "profile" && command != "certs") {
    return usage();
  }
  try {
    return command == "profile" ? profile(argc, argv) : certs(argc, argv);
  } catch (const std::exception& e) {
    error(e.what());
    return kExitFailure;
  }
}
