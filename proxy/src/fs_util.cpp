#include "llmfw/fs_util.hpp"

#include <cerrno>
#include <string>
#include <system_error>
#include <vector>

#include <sys/stat.h>

namespace llmfw {

namespace {

constexpr mode_t kDirMode = 0700;

[[noreturn]] void throwErrno(int error, const std::string& what) {
  throw std::system_error(error, std::generic_category(), what);
}

}  // namespace

void createPrivateDirectories(const std::filesystem::path& dir) {
  std::vector<std::filesystem::path> missing;
  for (std::filesystem::path p = dir; !p.empty() && !std::filesystem::exists(p); p = p.parent_path()) {
    missing.push_back(p);
    if (p == p.parent_path()) {
      break;
    }
  }
  for (auto it = missing.rbegin(); it != missing.rend(); ++it) {
    if (::mkdir(it->c_str(), kDirMode) != 0 && errno != EEXIST) {
      throwErrno(errno, "cannot create " + it->string());
    }
  }
}

}  // namespace llmfw
