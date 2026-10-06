// Stand-in for Claude's executable in the launcher tests. It writes its arguments,
// one per line, to $LLMFW_FAKE_CLAUDE_OUT (renamed into place so a reader never sees a
// partial file), then sleeps for $LLMFW_FAKE_CLAUDE_SLEEP_MS milliseconds.

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <thread>

int main(int argc, char** argv) {
  if (const char* out = std::getenv("LLMFW_FAKE_CLAUDE_OUT")) {
    const std::string temp = std::string(out) + ".tmp";
    if (std::FILE* f = std::fopen(temp.c_str(), "w")) {
      for (int i = 1; i < argc; ++i) {
        std::fprintf(f, "%s\n", argv[i]);
      }
      std::fclose(f);
      std::rename(temp.c_str(), out);
    }
  }
  if (const char* sleep_ms = std::getenv("LLMFW_FAKE_CLAUDE_SLEEP_MS")) {
    std::this_thread::sleep_for(std::chrono::milliseconds(std::atoi(sleep_ms)));
  }
  return 0;
}
