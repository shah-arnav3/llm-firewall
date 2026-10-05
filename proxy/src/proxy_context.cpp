#include "llmfw/proxy_context.hpp"

#include <vector>

#include "llmfw/blind_tunnel.hpp"

namespace llmfw {

bool TunnelRegistry::add(std::uint64_t connection_id, std::weak_ptr<BlindTunnel> tunnel) {
  const std::lock_guard lock(mu_);
  if (closing_) {
    return false;
  }
  open_[connection_id] = std::move(tunnel);
  return true;
}

void TunnelRegistry::remove(std::uint64_t connection_id) {
  std::function<void()> on_empty;
  {
    const std::lock_guard lock(mu_);
    open_.erase(connection_id);
    if (closing_ && open_.empty()) {
      on_empty = std::exchange(on_empty_, nullptr);
    }
  }
  if (on_empty) {
    on_empty();
  }
}

void TunnelRegistry::closeAll(std::function<void()> on_empty) {
  std::vector<std::shared_ptr<BlindTunnel>> to_close;
  bool nothing_open = false;
  {
    const std::lock_guard lock(mu_);
    closing_ = true;
    for (auto it = open_.begin(); it != open_.end();) {
      if (auto tunnel = it->second.lock()) {
        to_close.push_back(std::move(tunnel));
        ++it;
      } else {
        it = open_.erase(it);
      }
    }
    nothing_open = open_.empty();
    if (!nothing_open) {
      on_empty_ = std::move(on_empty);
    }
  }
  if (nothing_open && on_empty) {
    on_empty();
  }
  for (const auto& tunnel : to_close) {
    tunnel->close();
  }
}

std::size_t TunnelRegistry::size() const {
  const std::lock_guard lock(mu_);
  return open_.size();
}

}  // namespace llmfw
