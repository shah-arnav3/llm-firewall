// llmfw-proxy: the logging-only proxy for the Claude desktop app.
//
//   llmfw-proxy [--config <path>]   default: ~/Library/Application Support/llm-firewall/llm-firewall.yaml
//   llmfw-proxy --help | --version
//
// Exit codes are llmfw::ExitCode (proxy_context.hpp). Operational logs go to stderr;
// they carry hosts, counts and errors only, never header values or bodies.

#include <cstdio>
#include <exception>
#include <filesystem>
#include <optional>
#include <string_view>

#include "llmfw/config.hpp"
#include "llmfw/log.hpp"
#include "llmfw/proxy_context.hpp"

namespace {

constexpr std::string_view kUsage =
    "usage: llmfw-proxy [--config <path>]\n"
    "       llmfw-proxy --help | --version\n";

}  // namespace

int main(int argc, char** argv) {
  std::optional<std::filesystem::path> config_path;
  for (int i = 1; i < argc; ++i) {
    const std::string_view arg = argv[i];
    if (arg == "--help" || arg == "-h") {
      std::fputs(kUsage.data(), stdout);
      return llmfw::kExitOk;
    }
    if (arg == "--version") {
      std::puts("llmfw-proxy " LLMFW_VERSION);
      return llmfw::kExitOk;
    }
    if (arg == "--config" && i + 1 < argc) {
      config_path = argv[++i];
      continue;
    }
    std::fputs(kUsage.data(), stderr);
    return llmfw::kExitConfig;
  }

  try {
    const std::filesystem::path path = config_path ? *config_path : llmfw::defaultConfigPath();
    llmfw::ProxyApp app(llmfw::loadProxyConfig(path));
    return app.run();
  } catch (const llmfw::ConfigError& e) {
    llmfw::logError(std::string("configuration: ") + e.what());
    return llmfw::kExitConfig;
  } catch (const std::exception& e) {
    llmfw::logError(std::string("fatal: ") + e.what());
    return llmfw::kExitUnexpected;
  }
}
