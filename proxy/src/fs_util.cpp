#include "llmfw/fs_util.hpp"

#include <cerrno>
#include <string>
#include <system_error>
#include <vector>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

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

void writeFileAtomically(const std::filesystem::path& path, std::string_view contents, mode_t mode) {
  std::string temp = (path.parent_path() / ("." + path.filename().string() + ".XXXXXX")).string();
  const int fd = ::mkstemp(temp.data());
  if (fd < 0) {
    throwErrno(errno, "cannot create a temp file next to " + path.string());
  }
  const auto fail = [&](const std::string& what) {
    const int error = errno;
    ::close(fd);
    ::unlink(temp.c_str());
    throwErrno(error, what + " " + path.string());
  };
  if (::fchmod(fd, mode) != 0) {
    fail("cannot set the mode of");
  }
  for (std::size_t written = 0; written < contents.size();) {
    const ssize_t n = ::write(fd, contents.data() + written, contents.size() - written);
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      fail("cannot write");
    }
    written += static_cast<std::size_t>(n);
  }
  if (::fsync(fd) != 0) {
    fail("cannot flush");
  }
  if (::close(fd) != 0) {
    const int error = errno;
    ::unlink(temp.c_str());
    throwErrno(error, "cannot close " + path.string());
  }
  if (::rename(temp.c_str(), path.c_str()) != 0) {
    const int error = errno;
    ::unlink(temp.c_str());
    throwErrno(error, "cannot replace " + path.string());
  }
}

}  // namespace llmfw
