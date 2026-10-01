#include <gtest/gtest.h>

#include "llmfw/client_classifier.hpp"

namespace llmfw {
namespace {

TEST(ClientClassifier, FirstMatchingRuleWins) {
  const ClientClassifier classifier({{ClientPathTag::kClaudeCode, {"claude-cli/", "claude-code/"}},
                                     {ClientPathTag::kUi, {"Electron/", "Claude/"}}});
  EXPECT_EQ(classifier.classify("claude-cli/1.0 (external, cli) Electron/38"), ClientPathTag::kClaudeCode);
  EXPECT_EQ(classifier.classify("claude-code/2.0"), ClientPathTag::kClaudeCode);
  EXPECT_EQ(classifier.classify("Mozilla/5.0 Claude/2.9 Electron/38"), ClientPathTag::kUi);
  EXPECT_EQ(classifier.classify("curl/8.7"), ClientPathTag::kUnknown);
  EXPECT_EQ(classifier.classify(""), ClientPathTag::kUnknown);
}

TEST(ClientClassifier, MatchingIsCaseSensitive) {
  const ClientClassifier classifier({{ClientPathTag::kUi, {"Electron/"}}});
  EXPECT_EQ(classifier.classify("electron/38"), ClientPathTag::kUnknown);
}

TEST(ClientClassifier, NoRulesMeansUnknown) {
  EXPECT_EQ(ClientClassifier({}).classify("Mozilla/5.0 Claude/2.9 Electron/38"), ClientPathTag::kUnknown);
}

}  // namespace
}  // namespace llmfw
