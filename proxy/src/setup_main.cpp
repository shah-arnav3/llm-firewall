// llmfw-setup: sets Claude up so its traffic goes through llmfw-proxy.
//
//   llmfw-setup profile [--config <path>] [--output <path>] [--scope user|system]
//       Writes a macOS configuration profile that sets only Claude's egressProxyPacUrl to
//       the proxy's PAC (http://<listen address>:<port>/proxy.pac). It does not install
//       it; installing it is the user's step in System Settings.
//   llmfw-setup --help | --version
//
// Exit codes: 0 ok; 1 usage; 2 preflight failed (bad config); 4 other failure.

#include <cstdio>
#include <exception>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>

#include "llmfw/config.hpp"
#include "llmfw/pac.hpp"
#include "llmfw/random_id.hpp"
#include "llmfw/setup_paths.hpp"
#include "llmfw/setup_profile.hpp"

namespace {

enum SetupExit : int { kExitOk = 0, kExitUsage = 1, kExitPreflight = 2, kExitFailure = 4 };

constexpr std::string_view kUsage =
    "usage: llmfw-setup profile [--config <path>] [--output <path>] [--scope user|system]\n"
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
  if (command != "profile") {
    return usage();
  }
  try {
    return profile(argc, argv);
  } catch (const std::exception& e) {
    error(e.what());
    return kExitFailure;
  }
}
