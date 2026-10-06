#pragma once
// Every filesystem location llm-firewall creates or touches.

#include <filesystem>

namespace llmfw::setup {

/// Paths for the current user. The modes noted are the ones the setup tool applies
/// when it creates each path.
struct InstallPaths {
  std::filesystem::path home;
  std::filesystem::path app_support;        ///< ~/Library/Application Support/llm-firewall      (0700)
  std::filesystem::path config_file;        ///< <app_support>/llm-firewall.yaml                 (0600)
  std::filesystem::path pac_file;           ///< <app_support>/claude.pac                        (0644)
  std::filesystem::path certs_dir;          ///< <app_support>/certs                             (0700)
  std::filesystem::path ca_cert;            ///< <certs_dir>/ca.pem (public cert only)           (0644)
  std::filesystem::path leaf_cert;          ///< <certs_dir>/leaf.pem                            (0644)
  std::filesystem::path leaf_key;           ///< <certs_dir>/leaf.key                            (0600)
  std::filesystem::path run_dir;            ///< <app_support>/run (holds capture.sock)          (0700)
  std::filesystem::path models_dir;         ///< <app_support>/models (ONNX models, tokenizers)  (0700)
  std::filesystem::path bin_dir;            ///< <app_support>/bin
  std::filesystem::path database;           ///< <app_support>/llm-firewall.db                   (0600)
  std::filesystem::path manifest;           ///< <app_support>/install-manifest.json             (0600)
  std::filesystem::path logs_dir;           ///< ~/Library/Logs/llm-firewall                      (0700)
  std::filesystem::path launch_agents_dir;  ///< ~/Library/LaunchAgents
  std::filesystem::path proxy_plist;        ///< <launch_agents_dir>/dev.llmfirewall.proxy.plist
  std::filesystem::path collector_plist;    ///< <launch_agents_dir>/dev.llmfirewall.collector.plist
  std::filesystem::path launcher_app;       ///< ~/Applications/Claude (Monitored).app
  std::filesystem::path claude_app;         ///< /Applications/Claude.app

  /// Resolves every path from llmfw::homeDirectory(). Creates nothing.
  /// @throws ConfigError if the home directory cannot be determined.
  [[nodiscard]] static InstallPaths forCurrentUser();
};

inline constexpr const char* kProxyAgentLabel = "dev.llmfirewall.proxy";
inline constexpr const char* kCollectorAgentLabel = "dev.llmfirewall.collector";

}  // namespace llmfw::setup
