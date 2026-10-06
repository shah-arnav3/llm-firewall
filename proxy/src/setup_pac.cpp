#include "llmfw/setup_pac.hpp"

#include "llmfw/fs_util.hpp"
#include "llmfw/pac_template.hpp"

namespace llmfw::setup {

namespace {

constexpr std::string_view kPortToken = "{{PROXY_PORT}}";
constexpr mode_t kPacMode = 0644;

}  // namespace

std::string_view pacTemplate() { return kEmbeddedPacTemplate; }

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

}  // namespace llmfw::setup
