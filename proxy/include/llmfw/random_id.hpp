#pragma once
// Random identifiers.

#include <string>

namespace llmfw {

/// A random version 4 UUID in lower-case canonical form
/// ("xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx", y in 8-b), from std::random_device.
[[nodiscard]] std::string randomUuid();

}  // namespace llmfw
