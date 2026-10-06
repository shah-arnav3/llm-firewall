#pragma once
// Filesystem helpers for files that must stay private to the user.

#include <filesystem>

namespace llmfw {

/// Creates each missing directory on the way to `dir` with mode 0700, leaving
/// existing ones (such as ~/Library/Logs) untouched.
/// @throws std::system_error if a directory cannot be created.
void createPrivateDirectories(const std::filesystem::path& dir);

}  // namespace llmfw
