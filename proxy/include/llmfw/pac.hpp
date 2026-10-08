#pragma once
// The PAC file that routes only Claude's hosts to the proxy.

#include <cstdint>
#include <filesystem>
#include <stdexcept>
#include <string>
#include <string_view>

namespace llmfw {

/// The path the proxy serves the rendered PAC at.
inline constexpr std::string_view kPacPath = "/proxy.pac";

/// The URL Claude fetches the PAC from: "http://<address>:<port>/proxy.pac", with an
/// IPv6 address in brackets.
[[nodiscard]] std::string pacUrl(std::string_view listen_address, std::uint16_t port);

/// config/claude.pac, embedded at build time.
[[nodiscard]] std::string_view pacTemplate();

/// Thrown when a template still contains a "{{" token after rendering.
class TemplateError : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

/// Replaces every "{{PROXY_PORT}}" in `template_text` with `proxy_port`.
/// @throws TemplateError if any "{{" remains, so a PAC with an unknown token is never written.
[[nodiscard]] std::string renderPac(std::string_view template_text, std::uint16_t proxy_port);

/// Writes the rendered PAC to `pac_file` atomically with mode 0644 (Chromium reads it
/// as the user), creating missing parent directories with mode 0700.
/// @throws std::system_error on any filesystem failure.
void writePacFile(const std::filesystem::path& pac_file, std::string_view pac);

}  // namespace llmfw
