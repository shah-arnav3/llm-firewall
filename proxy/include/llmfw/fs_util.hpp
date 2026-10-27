#pragma once
// Filesystem helpers for files that must stay private to the user.

#include <filesystem>
#include <string>
#include <string_view>

#include <sys/types.h>

namespace llmfw {

/// Creates each missing directory on the way to `dir` with mode 0700, leaving
/// existing ones (such as ~/Library/Logs) untouched.
/// @throws std::system_error if a directory cannot be created.
void createPrivateDirectories(const std::filesystem::path& dir);

/// Replaces `path` with `contents` atomically: writes a temp file in the same
/// directory with `mode`, then renames it over `path`. Readers see the old or the new
/// file, never a partial one. The directory must exist.
/// @throws std::system_error on any failure; the temp file is removed.
void writeFileAtomically(const std::filesystem::path& path, std::string_view contents, mode_t mode);

/// Whether `dir` is a directory (not a symlink to one) owned by getuid() with mode
/// exactly 0700. False if it does not exist or cannot be examined.
[[nodiscard]] bool isPrivateDirectory(const std::filesystem::path& dir);

/// Whether `path` is a Unix domain socket (not a symlink to one) owned by getuid().
/// False if it does not exist or cannot be examined.
[[nodiscard]] bool isOwnSocket(const std::filesystem::path& path);

}  // namespace llmfw
