#include "llmfw/pac.hpp"

#include "llmfw/fs_util.hpp"
#include "llmfw/pac_template.hpp"

namespace llmfw {

namespace {

constexpr std::string_view kPortToken = "{{PROXY_PORT}}";
constexpr mode_t kPacMode = 0644;

}  // namespace

std::string_view pacTemplate() { return kEmbeddedPacTemplate; }

std::string pacUrl(std::string_view listen_address, std::uint16_t port) {
  const bool ipv6 = listen_address.find(':') != std::string_view::npos;
  return "http://" + (ipv6 ? "[" + std::string(listen_address) + "]" : std::string(listen_address)) + ":" +
         std::to_string(port) + std::string(kPacPath);
}

std::string renderPac(std::string_view template_text, std::uint16_t proxy_port) {
  std::string pac(template_text);
  const std::string port = std::to_string(proxy_port);
  for (std::size_t at = pac.find(kPortToken); at != std::string::npos; at = pac.find(kPortToken, at + port.size())) {
    pac.replace(at, kPortToken.size(), port);
  }
  if (const std::size_t left = pac.find("{{"); left != std::string::npos) {
    const std::size_t right = pac.find("}}", left);
    const std::string token = right == std::string::npos ? pac.substr(left, 2) : pac.substr(left, right - left + 2);
    throw TemplateError("PAC template has an unreplaced token: " + token);
  }
  return pac;
}

void writePacFile(const std::filesystem::path& pac_file, std::string_view pac) {
  createPrivateDirectories(pac_file.parent_path());
  writeFileAtomically(pac_file, pac, kPacMode);
}

}  // namespace llmfw
