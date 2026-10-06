#pragma once
// Proxy configuration: an in-memory view of config/llm-firewall.yaml
// (the version key and the proxy, scope, clients, certs, capture, ipc and metadata_log sections).

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <stdexcept>
#include <string>
#include <vector>

namespace llmfw {

/// Mirrors proto llmfw.v1.ClientPath. Kept separate so the config does not depend on generated code.
enum class ClientPathTag { kUnknown, kUi, kClaudeCode, kVm };

enum class CaptureMode {
  kMetadataOnly,  ///< "metadata_only": no bodies are captured; records go to the metadata log.
  kFull,          ///< "full": capped bodies are captured and sent to the collector socket.
};

enum class UpstreamTrustMode {
  kSystem,     ///< "system": macOS Security.framework trust evaluation (strict).
  kPemBundle,  ///< "pem_bundle": a fixed PEM bundle, for tests.
};

struct ClientRule {
  ClientPathTag path = ClientPathTag::kUnknown;
  std::vector<std::string> user_agent_contains;  ///< Any substring matches (case-sensitive). Never empty.
};

struct UpstreamConfig {
  std::chrono::milliseconds connect_timeout{10'000};
  std::chrono::milliseconds tls_handshake_timeout{10'000};
  UpstreamTrustMode trust = UpstreamTrustMode::kSystem;
  std::filesystem::path pem_bundle;  ///< Set only with kPemBundle.
};

struct ListenConfig {
  std::string address = "127.0.0.1";  ///< Always a loopback address.
  std::uint16_t port = 18443;
  unsigned io_threads = 2;
  std::chrono::milliseconds idle_timeout{300'000};
  std::chrono::milliseconds client_tls_breaker_cooldown{600'000};
  std::vector<std::string> client_alpn{"http/1.1"};
};

struct CertConfig {
  std::filesystem::path dir;
  std::string ca_cert_file = "ca.pem";
  std::string leaf_cert_file = "leaf.pem";
  std::string leaf_key_file = "leaf.key";
};

struct CaptureConfig {
  std::size_t queue_max_items = 1024;
  std::size_t queue_max_bytes = 256u << 20;
  std::size_t request_body_cap_bytes = 16u << 20;
  std::size_t response_body_cap_bytes = 8u << 20;
  std::size_t websocket_message_cap_bytes = 1u << 20;
  std::vector<std::string> redact_headers;  ///< Lower-cased.
};

struct IpcConfig {
  std::filesystem::path socket_dir;
  std::string socket_name = "capture.sock";
  std::size_t max_frame_bytes = 20u << 20;
  std::chrono::milliseconds reconnect_backoff_initial{250};
  std::chrono::milliseconds reconnect_backoff_max{10'000};
  std::chrono::milliseconds stats_interval{30'000};

  /// socket_dir / socket_name. A loaded config guarantees it is at most 103 bytes (the macOS sun_path limit).
  [[nodiscard]] std::filesystem::path socketPath() const;
};

struct MetadataLogConfig {
  std::filesystem::path path;
  std::size_t rotate_bytes = 50u << 20;
  unsigned keep_files = 5;
  std::vector<std::string> logged_header_values;  ///< Lower-cased.
};

struct ProxyConfig {
  ListenConfig listen;
  UpstreamConfig upstream;
  CaptureMode mode = CaptureMode::kMetadataOnly;
  std::vector<std::string> decrypt_hosts;  ///< Exact names or "*.suffix" patterns, lower-cased. Never empty.
  std::vector<ClientRule> clients;
  CertConfig certs;
  CaptureConfig capture;
  IpcConfig ipc;
  MetadataLogConfig metadata_log;
};

/// Thrown for a missing, malformed or invariant-violating configuration. The message
/// starts with the dotted key at fault, for example "proxy.listen_port: ...".
class ConfigError : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

/// Parses the YAML file, expands a leading "~/" in paths, applies defaults for
/// optional keys and validates every invariant:
///   - version is 1
///   - listen_address is a loopback IPv4 or IPv6 literal, and listen_port is 1-65535
///   - client_alpn lists only "http/1.1"
///   - decrypt_hosts is non-empty and every entry passes HostScope::isValidPattern
///   - every clients rule has a known path (UI, CLAUDE_CODE, VM) and at least one substring
///   - certs.dir, ipc.socket_dir and metadata_log.path are present
///   - the socket path is at most 103 bytes
///   - max_frame_bytes is at least the largest body cap plus 64 KiB
///   - every count, size and duration is positive (keep_files may be 0)
/// Keys outside these sections, such as the collector's, are ignored.
/// @throws ConfigError on an unreadable file, invalid YAML or any violation.
[[nodiscard]] ProxyConfig loadProxyConfig(const std::filesystem::path& file);

/// $HOME, or the passwd entry's home directory if $HOME is unset or empty.
/// @throws ConfigError if neither is available.
[[nodiscard]] std::filesystem::path homeDirectory();

/// ~/Library/Application Support/llm-firewall/llm-firewall.yaml
/// @throws ConfigError if the home directory cannot be determined.
[[nodiscard]] std::filesystem::path defaultConfigPath();

}  // namespace llmfw
