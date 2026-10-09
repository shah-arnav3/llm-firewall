#include "llmfw/setup_paths.hpp"

#include <string>

#include "llmfw/config.hpp"

namespace llmfw::setup {

InstallPaths InstallPaths::forCurrentUser() {
  InstallPaths p;
  p.home = homeDirectory();
  p.app_support = p.home / "Library" / "Application Support" / "llm-firewall";
  p.config_file = p.app_support / "llm-firewall.yaml";
  p.profile_file = p.app_support / "llm-firewall-claude-proxy.mobileconfig";
  p.certs_dir = p.app_support / "certs";
  p.ca_cert = p.certs_dir / "ca.pem";
  p.leaf_cert = p.certs_dir / "leaf.pem";
  p.leaf_key = p.certs_dir / "leaf.key";
  p.run_dir = p.app_support / "run";
  p.models_dir = p.app_support / "models";
  p.bin_dir = p.app_support / "bin";
  p.database = p.app_support / "llm-firewall.db";
  p.manifest = p.app_support / "install-manifest.json";
  p.logs_dir = p.home / "Library" / "Logs" / "llm-firewall";
  p.launch_agents_dir = p.home / "Library" / "LaunchAgents";
  p.proxy_plist = p.launch_agents_dir / (std::string(kProxyAgentLabel) + ".plist");
  p.collector_plist = p.launch_agents_dir / (std::string(kCollectorAgentLabel) + ".plist");
  return p;
}

}  // namespace llmfw::setup
