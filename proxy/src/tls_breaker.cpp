#include "llmfw/tls_breaker.hpp"

namespace llmfw {

ClientTlsBreaker::ClientTlsBreaker(std::chrono::milliseconds cooldown) : cooldown_(cooldown) {}

void ClientTlsBreaker::recordFailure(std::string_view normalized_host, Clock::time_point now) {
  const std::lock_guard lock(mu_);
  std::erase_if(open_until_, [now](const auto& entry) { return entry.second <= now; });
  open_until_[std::string(normalized_host)] = now + cooldown_;
}

bool ClientTlsBreaker::isOpen(std::string_view normalized_host, Clock::time_point now) const {
  const std::lock_guard lock(mu_);
  const auto it = open_until_.find(std::string(normalized_host));
  return it != open_until_.end() && now < it->second;
}

}  // namespace llmfw
