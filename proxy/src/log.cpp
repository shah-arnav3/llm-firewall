#include "llmfw/log.hpp"

#include <chrono>
#include <cstdio>
#include <ctime>
#include <string>

namespace llmfw {

namespace {

void writeLine(const char* level, std::string_view message) {
  const auto now = std::chrono::system_clock::now();
  const std::time_t seconds = std::chrono::system_clock::to_time_t(now);
  const auto millis =
      std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count() % 1000;
  std::tm utc{};
  ::gmtime_r(&seconds, &utc);
  char stamp[32];
  std::strftime(stamp, sizeof stamp, "%Y-%m-%dT%H:%M:%S", &utc);

  std::string line;
  line.reserve(message.size() + 48);
  line.append(stamp).append(".");
  const std::string ms = std::to_string(millis);
  line.append(3 - ms.size(), '0').append(ms).append("Z ").append(level).append(" ").append(message).append("\n");
  std::fwrite(line.data(), 1, line.size(), stderr);
}

}  // namespace

void logInfo(std::string_view message) { writeLine("INFO", message); }
void logWarn(std::string_view message) { writeLine("WARN", message); }
void logError(std::string_view message) { writeLine("ERROR", message); }

}  // namespace llmfw
