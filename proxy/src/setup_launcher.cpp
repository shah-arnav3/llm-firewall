#include "llmfw/setup_launcher.hpp"

#include <array>
#include <cerrno>
#include <system_error>

#include <fcntl.h>
#include <libproc.h>
#include <spawn.h>

extern char** environ;

namespace llmfw::setup {

namespace {

bool isUnreserved(unsigned char c) {
  return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.' ||
         c == '_' || c == '~';
}

std::string base64(std::string_view in) {
  static constexpr char kAlphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string out;
  out.reserve((in.size() + 2) / 3 * 4);
  std::size_t i = 0;
  for (; i + 2 < in.size(); i += 3) {
    const auto byte = [&](std::size_t k) { return static_cast<unsigned>(static_cast<unsigned char>(in[k])); };
    const unsigned n = (byte(i) << 16) | (byte(i + 1) << 8) | byte(i + 2);
    out.push_back(kAlphabet[(n >> 18) & 63]);
    out.push_back(kAlphabet[(n >> 12) & 63]);
    out.push_back(kAlphabet[(n >> 6) & 63]);
    out.push_back(kAlphabet[n & 63]);
  }
  if (const std::size_t rest = in.size() - i; rest > 0) {
    unsigned n = static_cast<unsigned>(static_cast<unsigned char>(in[i])) << 16;
    if (rest == 2) {
      n |= static_cast<unsigned>(static_cast<unsigned char>(in[i + 1])) << 8;
    }
    out.push_back(kAlphabet[(n >> 18) & 63]);
    out.push_back(kAlphabet[(n >> 12) & 63]);
    out.push_back(rest == 2 ? kAlphabet[(n >> 6) & 63] : '=');
    out.push_back('=');
  }
  return out;
}

std::filesystem::path resolved(const std::filesystem::path& path) {
  std::error_code ec;
  std::filesystem::path real = std::filesystem::weakly_canonical(path, ec);
  return ec ? path : real;
}

/// Closes the spawn attribute objects on every exit path.
struct SpawnSetup {
  posix_spawnattr_t attr{};
  posix_spawn_file_actions_t actions{};
  bool attr_ready = false;
  bool actions_ready = false;
  ~SpawnSetup() {
    if (actions_ready) {
      posix_spawn_file_actions_destroy(&actions);
    }
    if (attr_ready) {
      posix_spawnattr_destroy(&attr);
    }
  }
};

void check(int result, const char* what) {
  if (result != 0) {
    throw std::system_error(result, std::generic_category(), what);
  }
}

}  // namespace

std::string fileUrl(const std::filesystem::path& absolute_path) {
  static constexpr char kHex[] = "0123456789ABCDEF";
  std::string url = "file://";
  for (const char ch : absolute_path.string()) {
    const auto c = static_cast<unsigned char>(ch);
    if (isUnreserved(c) || c == '/') {
      url.push_back(ch);
    } else {
      url.push_back('%');
      url.push_back(kHex[c >> 4]);
      url.push_back(kHex[c & 0x0f]);
    }
  }
  return url;
}

std::string dataUrl(std::string_view pac) { return "data:application/x-ns-proxy-autoconfig;base64," + base64(pac); }

LaunchSpec buildLaunchSpec(const std::filesystem::path& claude_app, std::string_view pac_url) {
  return LaunchSpec{claude_app / "Contents" / "MacOS" / "Claude", {"--proxy-pac-url=" + std::string(pac_url)}};
}

std::vector<pid_t> runningProcessesAt(const std::filesystem::path& executable) {
  const std::filesystem::path wanted = resolved(executable);
  // The process table can grow between the two calls, so leave headroom.
  const int count = proc_listallpids(nullptr, 0);
  std::vector<pid_t> pids(static_cast<std::size_t>(count > 0 ? count : 0) + 64);
  const int filled = proc_listallpids(pids.data(), static_cast<int>(pids.size() * sizeof(pid_t)));
  pids.resize(static_cast<std::size_t>(filled > 0 ? filled : 0));

  std::vector<pid_t> matches;
  std::array<char, PROC_PIDPATHINFO_MAXSIZE> path{};
  for (const pid_t pid : pids) {
    if (pid > 0 && proc_pidpath(pid, path.data(), static_cast<std::uint32_t>(path.size())) > 0 &&
        resolved(path.data()) == wanted) {
      matches.push_back(pid);
    }
  }
  return matches;
}

pid_t launchDetached(const LaunchSpec& spec) {
  SpawnSetup setup;
  check(posix_spawnattr_init(&setup.attr), "posix_spawnattr_init");
  setup.attr_ready = true;
  check(posix_spawnattr_setflags(&setup.attr, POSIX_SPAWN_SETSID | POSIX_SPAWN_CLOEXEC_DEFAULT),
        "posix_spawnattr_setflags");
  check(posix_spawn_file_actions_init(&setup.actions), "posix_spawn_file_actions_init");
  setup.actions_ready = true;
  check(posix_spawn_file_actions_addopen(&setup.actions, 0, "/dev/null", O_RDONLY, 0), "open stdin");
  check(posix_spawn_file_actions_addopen(&setup.actions, 1, "/dev/null", O_WRONLY, 0), "open stdout");
  check(posix_spawn_file_actions_addopen(&setup.actions, 2, "/dev/null", O_WRONLY, 0), "open stderr");

  const std::string program = spec.executable.string();
  std::vector<char*> argv;
  argv.push_back(const_cast<char*>(program.c_str()));
  for (const std::string& arg : spec.args) {
    argv.push_back(const_cast<char*>(arg.c_str()));
  }
  argv.push_back(nullptr);

  pid_t pid = 0;
  check(posix_spawn(&pid, program.c_str(), &setup.actions, &setup.attr, argv.data(), environ),
        ("cannot start " + program).c_str());
  return pid;
}

}  // namespace llmfw::setup
