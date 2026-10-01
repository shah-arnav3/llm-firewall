#include "llmfw/config.hpp"

#include <algorithm>
#include <array>
#include <cstdlib>
#include <cstring>
#include <limits>

#include <arpa/inet.h>
#include <pwd.h>
#include <unistd.h>

#include <yaml-cpp/yaml.h>

#include "llmfw/host_scope.hpp"

namespace llmfw {

namespace {

constexpr std::size_t kMaxSocketPathBytes = 103;
constexpr std::size_t kFrameHeadroomBytes = 64u << 10;
constexpr long long kMaxBytes = 1LL << 40;
constexpr long long kMaxMillis = 24LL * 60 * 60 * 1000;

std::string toLower(std::string s) {
  std::transform(s.begin(), s.end(), s.begin(), [](char c) {
    return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
  });
  return s;
}

std::filesystem::path homeDirectory() {
  if (const char* home = std::getenv("HOME"); home != nullptr && *home != '\0') {
    return home;
  }
  if (const passwd* pw = getpwuid(getuid()); pw != nullptr && pw->pw_dir != nullptr) {
    return pw->pw_dir;
  }
  throw ConfigError("cannot determine the home directory ($HOME is unset and getpwuid failed)");
}

std::filesystem::path expandTilde(const std::string& raw) {
  if (raw == "~") {
    return homeDirectory();
  }
  if (raw.starts_with("~/")) {
    return homeDirectory() / raw.substr(2);
  }
  return raw;
}

bool isLoopbackLiteral(const std::string& address) {
  std::array<unsigned char, 16> addr{};
  if (inet_pton(AF_INET, address.c_str(), addr.data()) == 1) {
    return addr[0] == 127;
  }
  if (inet_pton(AF_INET6, address.c_str(), addr.data()) == 1) {
    return std::memcmp(addr.data(), &in6addr_loopback, addr.size()) == 0;
  }
  return false;
}

/// One YAML mapping plus its dotted path, so every error names the key at fault.
class Section {
 public:
  Section(YAML::Node node, std::string path) : node_(std::move(node)), path_(std::move(path)) {}

  [[nodiscard]] std::string where(const std::string& key) const { return path_.empty() ? key : path_ + "." + key; }

  [[noreturn]] void fail(const std::string& key, const std::string& message) const {
    throw ConfigError(where(key) + ": " + message);
  }

  [[nodiscard]] bool has(const std::string& key) const {
    return node_.IsMap() && node_[key].IsDefined() && !node_[key].IsNull();
  }

  /// A missing key gives an empty section, so its keys all fall back to defaults.
  [[nodiscard]] Section child(const std::string& key) const {
    if (!has(key)) {
      return Section(YAML::Node(YAML::NodeType::Map), where(key));
    }
    const YAML::Node value = node_[key];
    if (!value.IsMap()) {
      fail(key, "must be a mapping");
    }
    return Section(value, where(key));
  }

  [[nodiscard]] YAML::Node raw(const std::string& key) const { return node_[key]; }

  [[nodiscard]] std::string str(const std::string& key, std::string fallback) const {
    return has(key) ? scalar(key) : std::move(fallback);
  }

  [[nodiscard]] std::string requiredStr(const std::string& key) const {
    if (!has(key)) {
      fail(key, "is required");
    }
    std::string value = scalar(key);
    if (value.empty()) {
      fail(key, "must not be empty");
    }
    return value;
  }

  [[nodiscard]] long long integer(const std::string& key, long long fallback, long long min, long long max) const {
    if (!has(key)) {
      return fallback;
    }
    long long value = 0;
    try {
      value = node_[key].as<long long>();
    } catch (const YAML::Exception&) {
      fail(key, "must be an integer");
    }
    if (value < min || value > max) {
      fail(key, "must be between " + std::to_string(min) + " and " + std::to_string(max));
    }
    return value;
  }

  [[nodiscard]] std::size_t bytes(const std::string& key, std::size_t fallback) const {
    return static_cast<std::size_t>(integer(key, static_cast<long long>(fallback), 1, kMaxBytes));
  }

  [[nodiscard]] std::chrono::milliseconds millis(const std::string& key, std::chrono::milliseconds fallback) const {
    return std::chrono::milliseconds(integer(key, fallback.count(), 1, kMaxMillis));
  }

  [[nodiscard]] std::vector<std::string> strings(const std::string& key, std::vector<std::string> fallback) const {
    if (!has(key)) {
      return fallback;
    }
    const YAML::Node list = node_[key];
    if (!list.IsSequence()) {
      fail(key, "must be a list");
    }
    std::vector<std::string> out;
    for (const YAML::Node& item : list) {
      if (!item.IsScalar() || item.Scalar().empty()) {
        fail(key, "entries must be non-empty strings");
      }
      out.push_back(item.Scalar());
    }
    return out;
  }

 private:
  [[nodiscard]] std::string scalar(const std::string& key) const {
    const YAML::Node value = node_[key];
    if (!value.IsScalar()) {
      fail(key, "must be a string");
    }
    return value.Scalar();
  }

  YAML::Node node_;
  std::string path_;
};

ListenConfig parseListen(const Section& proxy) {
  ListenConfig cfg;
  cfg.address = proxy.str("listen_address", cfg.address);
  if (!isLoopbackLiteral(cfg.address)) {
    proxy.fail("listen_address", "must be a loopback address (127.0.0.0/8 or ::1), got \"" + cfg.address + "\"");
  }
  cfg.port = static_cast<std::uint16_t>(proxy.integer("listen_port", cfg.port, 1, 65535));
  cfg.io_threads = static_cast<unsigned>(proxy.integer("io_threads", cfg.io_threads, 1, 64));
  cfg.idle_timeout = proxy.millis("idle_timeout_ms", cfg.idle_timeout);
  cfg.client_tls_breaker_cooldown = proxy.millis("client_tls_breaker_cooldown_ms", cfg.client_tls_breaker_cooldown);
  cfg.client_alpn = proxy.strings("client_alpn", cfg.client_alpn);
  if (cfg.client_alpn.empty() ||
      !std::all_of(cfg.client_alpn.begin(), cfg.client_alpn.end(), [](const std::string& p) { return p == "http/1.1"; })) {
    proxy.fail("client_alpn", "only \"http/1.1\" is supported");
  }
  return cfg;
}

UpstreamConfig parseUpstream(const Section& upstream) {
  UpstreamConfig cfg;
  cfg.connect_timeout = upstream.millis("connect_timeout_ms", cfg.connect_timeout);
  cfg.tls_handshake_timeout = upstream.millis("tls_handshake_timeout_ms", cfg.tls_handshake_timeout);
  const std::string trust = upstream.str("trust", "system");
  if (trust == "system") {
    cfg.trust = UpstreamTrustMode::kSystem;
  } else if (trust == "pem_bundle") {
    cfg.trust = UpstreamTrustMode::kPemBundle;
    cfg.pem_bundle = expandTilde(upstream.requiredStr("pem_bundle"));
  } else {
    upstream.fail("trust", "must be \"system\" or \"pem_bundle\", got \"" + trust + "\"");
  }
  return cfg;
}

CaptureMode parseMode(const Section& proxy) {
  const std::string mode = proxy.str("mode", "metadata_only");
  if (mode == "metadata_only") {
    return CaptureMode::kMetadataOnly;
  }
  if (mode == "full") {
    return CaptureMode::kFull;
  }
  proxy.fail("mode", "must be \"metadata_only\" or \"full\", got \"" + mode + "\"");
}

std::vector<std::string> parseDecryptHosts(const Section& scope) {
  std::vector<std::string> hosts = scope.strings("decrypt_hosts", {});
  if (hosts.empty()) {
    scope.fail("decrypt_hosts", "must list at least one host");
  }
  for (std::string& host : hosts) {
    host = toLower(host);
    if (!HostScope::isValidPattern(host)) {
      scope.fail("decrypt_hosts", "invalid pattern \"" + host + "\" (expected \"name.tld\" or \"*.name.tld\")");
    }
  }
  return hosts;
}

ClientPathTag parseClientPath(const Section& rule, const std::string& name) {
  if (name == "UI") {
    return ClientPathTag::kUi;
  }
  if (name == "CLAUDE_CODE") {
    return ClientPathTag::kClaudeCode;
  }
  if (name == "VM") {
    return ClientPathTag::kVm;
  }
  rule.fail("path", "must be UI, CLAUDE_CODE or VM, got \"" + name + "\"");
}

std::vector<ClientRule> parseClients(const Section& root) {
  std::vector<ClientRule> rules;
  if (!root.has("clients")) {
    return rules;
  }
  const YAML::Node list = root.raw("clients");
  if (!list.IsSequence()) {
    root.fail("clients", "must be a list");
  }
  for (std::size_t i = 0; i < list.size(); ++i) {
    const std::string name = root.where("clients[" + std::to_string(i) + "]");
    if (!list[i].IsMap()) {
      throw ConfigError(name + ": must be a mapping");
    }
    const Section rule(list[i], name);
    ClientRule parsed;
    parsed.path = parseClientPath(rule, rule.requiredStr("path"));
    parsed.user_agent_contains = rule.strings("user_agent_contains", {});
    if (parsed.user_agent_contains.empty()) {
      rule.fail("user_agent_contains", "must list at least one substring");
    }
    rules.push_back(std::move(parsed));
  }
  return rules;
}

CertConfig parseCerts(const Section& certs) {
  CertConfig cfg;
  cfg.dir = expandTilde(certs.requiredStr("dir"));
  cfg.ca_cert_file = certs.str("ca_cert_file", cfg.ca_cert_file);
  cfg.leaf_cert_file = certs.str("leaf_cert_file", cfg.leaf_cert_file);
  cfg.leaf_key_file = certs.str("leaf_key_file", cfg.leaf_key_file);
  return cfg;
}

CaptureConfig parseCapture(const Section& capture) {
  CaptureConfig cfg;
  cfg.queue_max_items = static_cast<std::size_t>(
      capture.integer("queue_max_items", static_cast<long long>(cfg.queue_max_items), 1, 1'000'000));
  cfg.queue_max_bytes = capture.bytes("queue_max_bytes", cfg.queue_max_bytes);
  cfg.request_body_cap_bytes = capture.bytes("request_body_cap_bytes", cfg.request_body_cap_bytes);
  cfg.response_body_cap_bytes = capture.bytes("response_body_cap_bytes", cfg.response_body_cap_bytes);
  cfg.websocket_message_cap_bytes = capture.bytes("websocket_message_cap_bytes", cfg.websocket_message_cap_bytes);
  for (const std::string& name : capture.strings("redact_headers", {})) {
    cfg.redact_headers.push_back(toLower(name));
  }
  return cfg;
}

IpcConfig parseIpc(const Section& ipc, const CaptureConfig& capture) {
  IpcConfig cfg;
  cfg.socket_dir = expandTilde(ipc.requiredStr("socket_dir"));
  cfg.socket_name = ipc.str("socket_name", cfg.socket_name);
  if (cfg.socket_name.find('/') != std::string::npos) {
    ipc.fail("socket_name", "must be a file name, not a path");
  }
  const std::size_t socket_path_bytes = cfg.socketPath().string().size();
  if (socket_path_bytes > kMaxSocketPathBytes) {
    ipc.fail("socket_dir", "socket path is " + std::to_string(socket_path_bytes) + " bytes; macOS allows at most " +
                               std::to_string(kMaxSocketPathBytes));
  }
  cfg.max_frame_bytes = ipc.bytes("max_frame_bytes", cfg.max_frame_bytes);
  const std::size_t largest_cap = std::max(
      {capture.request_body_cap_bytes, capture.response_body_cap_bytes, capture.websocket_message_cap_bytes});
  if (cfg.max_frame_bytes < largest_cap + kFrameHeadroomBytes) {
    ipc.fail("max_frame_bytes", "must be at least the largest body cap (" + std::to_string(largest_cap) +
                                    ") plus 65536 bytes of headroom");
  }
  cfg.reconnect_backoff_initial = ipc.millis("reconnect_backoff_initial_ms", cfg.reconnect_backoff_initial);
  cfg.reconnect_backoff_max = ipc.millis("reconnect_backoff_max_ms", cfg.reconnect_backoff_max);
  if (cfg.reconnect_backoff_initial > cfg.reconnect_backoff_max) {
    ipc.fail("reconnect_backoff_initial_ms", "must not exceed reconnect_backoff_max_ms");
  }
  cfg.stats_interval = ipc.millis("stats_interval_ms", cfg.stats_interval);
  return cfg;
}

MetadataLogConfig parseMetadataLog(const Section& log) {
  MetadataLogConfig cfg;
  cfg.path = expandTilde(log.requiredStr("path"));
  cfg.rotate_bytes = log.bytes("rotate_bytes", cfg.rotate_bytes);
  cfg.keep_files = static_cast<unsigned>(log.integer("keep_files", cfg.keep_files, 0, 100));
  for (const std::string& name : log.strings("logged_header_values", {})) {
    cfg.logged_header_values.push_back(toLower(name));
  }
  return cfg;
}

}  // namespace

std::filesystem::path IpcConfig::socketPath() const { return socket_dir / socket_name; }

ProxyConfig loadProxyConfig(const std::filesystem::path& file) {
  YAML::Node doc;
  try {
    doc = YAML::LoadFile(file.string());
  } catch (const YAML::BadFile&) {
    throw ConfigError(file.string() + ": cannot read the file");
  } catch (const YAML::Exception& e) {
    throw ConfigError(file.string() + ": invalid YAML: " + e.what());
  }
  if (!doc.IsMap()) {
    throw ConfigError(file.string() + ": the top level must be a mapping");
  }

  const Section root(doc, "");
  if (root.integer("version", 0, 0, std::numeric_limits<int>::max()) != 1) {
    root.fail("version", "must be 1");
  }

  const Section proxy = root.child("proxy");
  ProxyConfig cfg;
  cfg.listen = parseListen(proxy);
  cfg.upstream = parseUpstream(proxy.child("upstream"));
  cfg.mode = parseMode(proxy);
  cfg.decrypt_hosts = parseDecryptHosts(root.child("scope"));
  cfg.clients = parseClients(root);
  cfg.certs = parseCerts(root.child("certs"));
  cfg.capture = parseCapture(root.child("capture"));
  cfg.ipc = parseIpc(root.child("ipc"), cfg.capture);
  cfg.metadata_log = parseMetadataLog(root.child("metadata_log"));
  return cfg;
}

std::filesystem::path defaultConfigPath() {
  return homeDirectory() / "Library" / "Application Support" / "llm-firewall" / "llm-firewall.yaml";
}

}  // namespace llmfw
