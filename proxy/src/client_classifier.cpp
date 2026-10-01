#include "llmfw/client_classifier.hpp"

#include <algorithm>

namespace llmfw {

ClientClassifier::ClientClassifier(std::vector<ClientRule> rules) : rules_(std::move(rules)) {}

ClientPathTag ClientClassifier::classify(std::string_view user_agent) const {
  if (user_agent.empty()) {
    return ClientPathTag::kUnknown;
  }
  for (const ClientRule& rule : rules_) {
    const bool matches = std::any_of(rule.user_agent_contains.begin(), rule.user_agent_contains.end(),
                                     [&](const std::string& needle) {
                                       return user_agent.find(needle) != std::string_view::npos;
                                     });
    if (matches) {
      return rule.path;
    }
  }
  return ClientPathTag::kUnknown;
}

}  // namespace llmfw
