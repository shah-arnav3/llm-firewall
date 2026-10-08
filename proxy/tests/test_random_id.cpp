#include <gtest/gtest.h>

#include <regex>
#include <set>

#include "llmfw/random_id.hpp"

namespace llmfw {
namespace {

TEST(RandomUuid, IsCanonicalVersion4) {
  const std::regex v4("^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$");
  for (int i = 0; i < 100; ++i) {
    const std::string id = randomUuid();
    EXPECT_TRUE(std::regex_match(id, v4)) << id;
  }
}

TEST(RandomUuid, DoesNotRepeat) {
  std::set<std::string> seen;
  for (int i = 0; i < 1000; ++i) {
    EXPECT_TRUE(seen.insert(randomUuid()).second);
  }
}

}  // namespace
}  // namespace llmfw
