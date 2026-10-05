#pragma once
// Operational log lines on stderr. They carry hosts, counts and errors only, never
// header values or bodies.

#include <string_view>

namespace llmfw {

/// Writes "<UTC ISO-8601 time> <LEVEL> <message>\n" to stderr in one call, so lines
/// from different threads never interleave.
void logInfo(std::string_view message);
void logWarn(std::string_view message);
void logError(std::string_view message);

}  // namespace llmfw
