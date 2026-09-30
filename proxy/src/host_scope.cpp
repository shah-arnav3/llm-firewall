#include "llmfw/host_scope.hpp"

#include <algorithm>
#include <array>

#include <arpa/inet.h>

namespace llmfw {

namespace {

constexpr std::size_t kMaxHostLength = 253;
constexpr std::size_t kMaxLabelLength = 63;
constexpr std::uint16_t kTlsPort = 443;

bool isIpLiteral(const std::string& host) {
  std::array<unsigned char, 16> addr{};
  return inet_pton(AF_INET, host.c_str(), addr.data()) == 1 || inet_pton(AF_INET6, host.c_str(), addr.data()) == 1;
}

bool isLdh(char c) {
  return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-';
}

bool labelsAreValid(std::string_view host) {
  std::size_t start = 0;
  while (start <= host.size()) {
    const std::size_t dot = host.find('.', start);
    const std::size_t end = dot == std::string_view::npos ? host.size() : dot;
    const std::string_view label = host.substr(start, end - start);
    if (label.empty() || label.size() > kMaxLabelLength || label.front() == '-' || label.back() == '-' ||
        !std::all_of(label.begin(), label.end(), isLdh)) {
      return false;
    }
    if (dot == std::string_view::npos) {
      return true;
    }
    start = dot + 1;
  }
  return false;
}

}  // namespace

HostScope::HostScope(std::vector<std::string> patterns) : patterns_(std::move(patterns)) {}

bool HostScope::inScope(std::string_view normalized_host) const {
  return std::any_of(patterns_.begin(), patterns_.end(),
                     [&](const std::string& pattern) { return matchesPattern(pattern, normalized_host); });
}

std::optional<std::string> HostScope::normalizeHost(std::string_view raw) {
  if (!raw.empty() && raw.back() == '.') {
    raw.remove_suffix(1);
  }
  if (raw.empty() || raw.size() > kMaxHostLength) {
    return std::nullopt;
  }
  std::string host(raw);
  std::transform(host.begin(), host.end(), host.begin(), [](char c) {
    return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
  });
  if (isIpLiteral(host) || !labelsAreValid(host)) {
    return std::nullopt;
  }
  return host;
}

bool HostScope::isValidPattern(std::string_view pattern) {
  const std::string_view name = pattern.starts_with("*.") ? pattern.substr(2) : pattern;
  const auto normalized = normalizeHost(name);
  return normalized && *normalized == name && name.find('.') != std::string_view::npos;
}

bool HostScope::matchesPattern(std::string_view pattern, std::string_view normalized_host) {
  if (!pattern.starts_with("*.")) {
    return pattern == normalized_host;
  }
  const std::string_view suffix = pattern.substr(1);  // ".example.com"
  return normalized_host.size() > suffix.size() && normalized_host.ends_with(suffix);
}

ScopeResult decideScope(std::string_view raw_host, std::uint16_t port, const HostScope& scope) {
  ScopeResult result;
  const auto host = HostScope::normalizeHost(raw_host);
  if (!host) {
    return result;
  }
  result.normalized_host = *host;
  if (!scope.inScope(*host)) {
    result.reason = TunnelReasonTag::kUnscopedHost;
  } else if (port != kTlsPort) {
    result.reason = TunnelReasonTag::kNonTlsPort;
  } else {
    result.reason = TunnelReasonTag::kScopedNoCert;
  }
  return result;
}

}  // namespace llmfw
