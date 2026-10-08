#include "llmfw/setup_profile.hpp"

#include "llmfw/fs_util.hpp"

namespace llmfw::setup {

namespace {

constexpr mode_t kProfileMode = 0644;

std::string xmlEscape(std::string_view text) {
  std::string out;
  out.reserve(text.size());
  for (const char c : text) {
    switch (c) {
      case '&': out += "&amp;"; break;
      case '<': out += "&lt;"; break;
      case '>': out += "&gt;"; break;
      case '"': out += "&quot;"; break;
      case '\'': out += "&apos;"; break;
      default: out.push_back(c); break;
    }
  }
  return out;
}

std::string str(std::string_view value) { return "<string>" + xmlEscape(value) + "</string>"; }

}  // namespace

std::string buildEgressProxyProfile(std::string_view pac_url, ProfileScope scope, std::string_view profile_uuid,
                                    std::string_view payload_uuid) {
  const std::string identifier(kProfileIdentifier);
  std::string xml;
  xml += "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
  xml += "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n";
  xml += "<plist version=\"1.0\">\n<dict>\n";
  xml += "  <key>PayloadContent</key>\n  <array>\n    <dict>\n";
  xml += "      <key>egressProxyPacUrl</key>\n      " + str(pac_url) + "\n";
  xml += "      <key>PayloadType</key>\n      " + str(kClaudePreferenceDomain) + "\n";
  xml += "      <key>PayloadIdentifier</key>\n      " + str(identifier + ".claude") + "\n";
  xml += "      <key>PayloadUUID</key>\n      " + str(payload_uuid) + "\n";
  xml += "      <key>PayloadVersion</key>\n      <integer>1</integer>\n";
  xml += "      <key>PayloadDisplayName</key>\n      " + str("Claude egress proxy (PAC)") + "\n";
  xml += "    </dict>\n  </array>\n";
  xml += "  <key>PayloadType</key>\n  " + str("Configuration") + "\n";
  xml += "  <key>PayloadIdentifier</key>\n  " + str(identifier) + "\n";
  xml += "  <key>PayloadUUID</key>\n  " + str(profile_uuid) + "\n";
  xml += "  <key>PayloadVersion</key>\n  <integer>1</integer>\n";
  xml += "  <key>PayloadScope</key>\n  " + str(scope == ProfileScope::kUser ? "User" : "System") + "\n";
  xml += "  <key>PayloadDisplayName</key>\n  " + str("llm-firewall: route Claude through the local proxy") + "\n";
  xml += "  <key>PayloadDescription</key>\n  " +
         str("Sets only Claude Desktop's egressProxyPacUrl to " + std::string(pac_url) +
             ", so Claude's traffic to claude.ai and anthropic.com goes through the local llm-firewall proxy. "
             "Remove this profile to stop.") +
         "\n";
  xml += "  <key>PayloadRemovalDisallowed</key>\n  <false/>\n";
  xml += "</dict>\n</plist>\n";
  return xml;
}

void writeProfile(const std::filesystem::path& output, std::string_view profile) {
  createPrivateDirectories(output.parent_path());
  writeFileAtomically(output, profile, kProfileMode);
}

}  // namespace llmfw::setup
