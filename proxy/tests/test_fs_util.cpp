#include <gtest/gtest.h>

#include <cstdio>
#include <filesystem>
#include <initializer_list>
#include <string>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include "llmfw/fs_util.hpp"

namespace llmfw {
namespace {

namespace fs = std::filesystem;

/// A fresh directory under /tmp (short, for socket paths), removed with its contents.
class TempDir {
 public:
  TempDir() {
    std::string tmpl = "/tmp/llmfw-fs-XXXXXX";
    path_ = ::mkdtemp(tmpl.data());
  }
  ~TempDir() { fs::remove_all(path_); }
  TempDir(const TempDir&) = delete;
  TempDir& operator=(const TempDir&) = delete;
  [[nodiscard]] const fs::path& path() const { return path_; }

 private:
  fs::path path_;
};

/// Binds a Unix socket at `path` and closes the descriptor, leaving the socket file.
void makeSocketFile(const fs::path& path) {
  const int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
  ASSERT_GE(fd, 0);
  sockaddr_un addr{};
  addr.sun_family = AF_UNIX;
  ASSERT_LT(path.string().size(), sizeof(addr.sun_path));
  path.string().copy(addr.sun_path, sizeof(addr.sun_path) - 1);
  ASSERT_EQ(::bind(fd, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)), 0);
  ::close(fd);
}

TEST(IsPrivateDirectory, AcceptsAnOwnDirectoryWithMode0700) {
  const TempDir tmp;
  EXPECT_TRUE(isPrivateDirectory(tmp.path())) << "mkdtemp creates 0700";
}

TEST(IsPrivateDirectory, RefusesAnyOtherMode) {
  const TempDir tmp;
  for (const mode_t mode : std::initializer_list<mode_t>{0750, 0755, 0701, 0600, 01700}) {
    ASSERT_EQ(::chmod(tmp.path().c_str(), mode), 0);
    EXPECT_FALSE(isPrivateDirectory(tmp.path())) << std::oct << mode;
  }
}

TEST(IsPrivateDirectory, RefusesASymlinkAFileAndAMissingPath) {
  const TempDir tmp;
  const fs::path dir = tmp.path() / "dir";
  fs::create_directory(dir);
  ASSERT_EQ(::chmod(dir.c_str(), 0700), 0);
  fs::create_directory_symlink(dir, tmp.path() / "link");
  EXPECT_TRUE(isPrivateDirectory(dir));
  EXPECT_FALSE(isPrivateDirectory(tmp.path() / "link"));
  const fs::path file = tmp.path() / "file";
  std::fclose(std::fopen(file.c_str(), "w"));
  ASSERT_EQ(::chmod(file.c_str(), 0700), 0);
  EXPECT_FALSE(isPrivateDirectory(file));
  EXPECT_FALSE(isPrivateDirectory(tmp.path() / "missing"));
}

TEST(IsPrivateDirectory, RefusesADirectoryOwnedBySomeoneElse) {
  EXPECT_FALSE(isPrivateDirectory("/var/root")) << "owned by root";
}

TEST(IsOwnSocket, AcceptsOurSocketAndRefusesEverythingElse) {
  const TempDir tmp;
  const fs::path sock = tmp.path() / "s.sock";
  makeSocketFile(sock);
  EXPECT_TRUE(isOwnSocket(sock));
  fs::create_symlink(sock, tmp.path() / "link.sock");
  EXPECT_FALSE(isOwnSocket(tmp.path() / "link.sock"));
  EXPECT_FALSE(isOwnSocket(tmp.path()));
  EXPECT_FALSE(isOwnSocket(tmp.path() / "missing.sock"));
}

}  // namespace
}  // namespace llmfw
