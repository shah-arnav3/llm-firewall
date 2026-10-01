#pragma once
// Assigns a ClientPath from the User-Agent, using the config `clients` rules.

#include <string_view>
#include <vector>

#include "llmfw/config.hpp"

namespace llmfw {

/// Rules are evaluated in order. The first rule with any matching substring wins.
/// No match, or an empty User-Agent, gives kUnknown. Web clients are added through
/// config, not code.
class ClientClassifier {
 public:
  explicit ClientClassifier(std::vector<ClientRule> rules);
  [[nodiscard]] ClientPathTag classify(std::string_view user_agent) const;

 private:
  std::vector<ClientRule> rules_;
};

}  // namespace llmfw
