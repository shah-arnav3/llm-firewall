#pragma once
// The macOS configuration profile that points Claude at the proxy's PAC.
//
// Claude Desktop reads `egressProxyPacUrl` once at launch from
// /Library/Managed Preferences/[<user>/]com.anthropic.claudefordesktop.plist, which macOS
// writes when a profile carrying that payload is installed. A profile that sets only
// this key changes Claude's proxy and nothing else. With it, the app, the Claude Code
// engine and the Cowork VM all follow the PAC.

#include <filesystem>
#include <string>
#include <string_view>

namespace llmfw::setup {

/// Stable across regenerations, so installing a new profile replaces the old one.
inline constexpr std::string_view kProfileIdentifier = "dev.llmfirewall.claude-egress-proxy";
inline constexpr std::string_view kClaudePreferenceDomain = "com.anthropic.claudefordesktop";

enum class ProfileScope {
  kUser,    ///< Installed for the current user; lands in Managed Preferences/<user>/.
  kSystem,  ///< Installed for the whole Mac (asks for an administrator password).
};

/// The .mobileconfig XML: one Configuration profile holding one
/// com.anthropic.claudefordesktop payload whose only key is egressProxyPacUrl.
/// `profile_uuid` and `payload_uuid` must be distinct UUIDs. String values are XML-escaped.
[[nodiscard]] std::string buildEgressProxyProfile(std::string_view pac_url, ProfileScope scope,
                                                  std::string_view profile_uuid, std::string_view payload_uuid);

/// Writes the profile atomically with mode 0644, creating missing parent directories
/// with mode 0700. It does not install it.
/// @throws std::system_error on any filesystem failure.
void writeProfile(const std::filesystem::path& output, std::string_view profile);

}  // namespace llmfw::setup
