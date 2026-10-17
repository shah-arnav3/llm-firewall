#pragma once
// Fail-open guard. If a client rejects our leaf certificate for a host (for
// example, the CA was removed from the Keychain or a component pins its
// certificates), later CONNECTs to that host are blind-tunneled for a cooldown.
// This way the client's retry succeeds instead of Claude breaking.

#include <chrono>
#include <mutex>
#include <string>
#include <string_view>
#include <unordered_map>

#include "llmfw/common.hpp"

namespace llmfw {

/// Thread-safe. Each call holds the lock for O(1) work, except recordFailure, which
/// also drops expired hosts so the map only holds hosts still in their cooldown.
class ClientTlsBreaker {
 public:
  explicit ClientTlsBreaker(std::chrono::milliseconds cooldown);

  /// Call when the client aborts our server-side handshake: an alert such as
  /// unknown_ca or bad_certificate, or EOF during the handshake. Opens the breaker
  /// for `host` until now + cooldown, extending an earlier window.
  void recordFailure(std::string_view normalized_host, Clock::time_point now);

  /// True while `host` is inside its cooldown window. True means blind-tunnel it.
  [[nodiscard]] bool isOpen(std::string_view normalized_host, Clock::time_point now) const;

 private:
  std::chrono::milliseconds cooldown_;
  mutable std::mutex mu_;
  std::unordered_map<std::string, Clock::time_point> open_until_;
};

}  // namespace llmfw
