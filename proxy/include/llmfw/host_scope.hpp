#pragma once
// Scope decision for a CONNECT target.

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "llmfw/common.hpp"

namespace llmfw {

class ClientTlsBreaker;
class LeafCertStore;

struct ScopeResult {
  /// Why the target is tunneled, or kNone if it should be decrypted.
  TunnelReasonTag reason = TunnelReasonTag::kUnscopedHost;
  std::string normalized_host;  ///< Empty when the host failed normalization.
};

/// Matches hosts against scope.decrypt_hosts.
/// Pattern rules: "example.com" matches only that name. "*.example.com" matches any
/// name ending in ".example.com" (one or more labels) and never matches
/// "example.com" itself.
class HostScope {
 public:
  /// @param patterns lower-cased, already validated with isValidPattern().
  explicit HostScope(std::vector<std::string> patterns);

  [[nodiscard]] bool inScope(std::string_view normalized_host) const;

  /// Lower-cases the host and strips one trailing dot. Returns nullopt for an empty
  /// host, an IP literal, bytes that are not letters, digits, hyphens or dots, an empty
  /// label, a label that starts or ends with a hyphen, a label longer than 63, or a
  /// total length over 253. IP literals are never in scope.
  [[nodiscard]] static std::optional<std::string> normalizeHost(std::string_view raw);

  /// True for "name" or "*.name" where name is already normalized (see normalizeHost)
  /// and has at least two labels, so "*.com" is rejected.
  [[nodiscard]] static bool isValidPattern(std::string_view pattern);

  [[nodiscard]] static bool matchesPattern(std::string_view pattern, std::string_view normalized_host);

 private:
  std::vector<std::string> patterns_;
};

/// Decides whether a CONNECT target is decrypted. Checks run in this order, and the first hit wins:
///   1. host fails normalization, or is not in scope       -> kUnscopedHost
///   2. port != 443                                        -> kNonTlsPort
///   3. no cert store, or no leaf SAN covers the host       -> kScopedNoCert
///   4. the breaker is open for the host at `now`          -> kClientTlsBreaker
///   5. otherwise                                          -> kNone (decrypt)
/// With `certs` null (decryption off), no target is ever decrypted. `breaker` may be null.
[[nodiscard]] ScopeResult decideScope(std::string_view raw_host, std::uint16_t port, const HostScope& scope,
                                      const LeafCertStore* certs = nullptr, const ClientTlsBreaker* breaker = nullptr,
                                      Clock::time_point now = {});

}  // namespace llmfw
