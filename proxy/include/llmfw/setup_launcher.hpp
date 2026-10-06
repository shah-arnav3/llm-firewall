#pragma once
// Starts Claude.app with the PAC flag, which is what routes its traffic to the proxy.
// Launching Claude any other way bypasses llm-firewall, and Claude still works.

#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

#include <sys/types.h>

namespace llmfw::setup {

struct LaunchSpec {
  std::filesystem::path executable;  ///< <claude_app>/Contents/MacOS/Claude
  std::vector<std::string> args;     ///< Arguments after argv[0].
};

/// "file://" plus `absolute_path`, percent-encoding every byte other than unreserved
/// characters and "/" (so "Application Support" becomes "Application%20Support").
[[nodiscard]] std::string fileUrl(const std::filesystem::path& absolute_path);

/// "data:application/x-ns-proxy-autoconfig;base64,<pac>". A fallback for when
/// Chromium does not accept a file:// PAC URL.
[[nodiscard]] std::string dataUrl(std::string_view pac);

/// Claude's executable with the single argument "--proxy-pac-url=<pac_url>". The
/// environment is inherited unchanged: the Claude Code path (HTTPS_PROXY) is not
/// routed yet.
[[nodiscard]] LaunchSpec buildLaunchSpec(const std::filesystem::path& claude_app, std::string_view pac_url);

/// Pids of running processes whose executable is `executable` (compared after
/// resolving symlinks). Processes this user cannot inspect are skipped.
[[nodiscard]] std::vector<pid_t> runningProcessesAt(const std::filesystem::path& executable);

/// Spawns the executable directly (not through `open`, which ignores extra arguments
/// for an app that is not running) in a new session, with stdin, stdout and stderr on
/// /dev/null and no other file descriptors inherited. Returns at once with the child's
/// pid; it never waits for Claude.
/// @throws std::system_error if the spawn fails.
pid_t launchDetached(const LaunchSpec& spec);

}  // namespace llmfw::setup
