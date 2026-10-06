#include "llmfw/metadata_logger.hpp"

#include <algorithm>
#include <cerrno>
#include <system_error>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <google/protobuf/util/json_util.h>

#include "llmfw/fs_util.hpp"

namespace llmfw {

namespace {

constexpr mode_t kFileMode = 0600;

[[noreturn]] void throwErrno(const std::string& what) {
  throw std::system_error(errno, std::generic_category(), what);
}

std::filesystem::path rotated(const std::filesystem::path& path, unsigned n) {
  return path.string() + "." + std::to_string(n);
}

}  // namespace

llmfw::v1::MetadataRecord toMetadataRecord(const llmfw::v1::Capture& capture, const MetadataLogConfig& cfg,
                                           const std::string& proxy_instance_id) {
  llmfw::v1::MetadataRecord record;
  record.set_proxy_instance_id(proxy_instance_id);
  record.set_capture_id(capture.capture_id());
  record.set_connection_id(capture.connection_id());
  record.set_exchange_index(capture.exchange_index());
  record.set_client_path(capture.client().path());
  *record.mutable_timings() = capture.timings();

  const auto& allowed = cfg.logged_header_values;
  if (std::find(allowed.begin(), allowed.end(), "user-agent") != allowed.end()) {
    record.set_user_agent(capture.client().user_agent());
  }

  switch (capture.payload_case()) {
    case llmfw::v1::Capture::kTunnel: {
      const llmfw::v1::TunnelSummary& tunnel = capture.tunnel();
      record.set_kind("tunnel");
      record.set_host(tunnel.host());
      record.set_tunnel_reason(tunnel.reason());
      record.set_request_bytes(tunnel.bytes_client_to_server());
      record.set_response_bytes(tunnel.bytes_server_to_client());
      record.set_tunnel_duration_us(tunnel.duration_us());
      break;
    }
    case llmfw::v1::Capture::kHttp: record.set_kind("http"); break;
    case llmfw::v1::Capture::kWebsocket: record.set_kind("websocket"); break;
    case llmfw::v1::Capture::PAYLOAD_NOT_SET: break;
  }
  return record;
}

MetadataLogger::MetadataLogger(MetadataLogConfig cfg, std::string proxy_instance_id)
    : cfg_(std::move(cfg)), proxy_instance_id_(std::move(proxy_instance_id)) {
  createPrivateDirectories(cfg_.path.parent_path());
  open();
}

MetadataLogger::~MetadataLogger() { close(); }

void MetadataLogger::open() {
  const int fd = ::open(cfg_.path.c_str(), O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC | O_NOFOLLOW, kFileMode);
  if (fd < 0) {
    throwErrno("cannot open " + cfg_.path.string());
  }
  struct stat st {};
  if (::fchmod(fd, kFileMode) != 0 || ::fstat(fd, &st) != 0) {
    const int saved = errno;
    ::close(fd);
    errno = saved;
    throwErrno("cannot set up " + cfg_.path.string());
  }
  file_ = ::fdopen(fd, "a");
  if (file_ == nullptr) {
    const int saved = errno;
    ::close(fd);
    errno = saved;
    throwErrno("cannot open " + cfg_.path.string());
  }
  written_ = static_cast<std::size_t>(st.st_size);
}

bool MetadataLogger::rotate() {
  close();
  // Best effort: if a step fails, the steps after it are skipped and logging continues
  // in whatever file is now at the path, which may grow past rotate_bytes.
  std::error_code ec;
  if (cfg_.keep_files == 0) {
    std::filesystem::remove(cfg_.path, ec);
  } else {
    std::filesystem::remove(rotated(cfg_.path, cfg_.keep_files), ec);
    for (unsigned n = cfg_.keep_files - 1; n >= 1 && !ec; --n) {
      if (std::filesystem::exists(rotated(cfg_.path, n))) {
        std::filesystem::rename(rotated(cfg_.path, n), rotated(cfg_.path, n + 1), ec);
      }
    }
    if (!ec) {
      std::filesystem::rename(cfg_.path, rotated(cfg_.path, 1), ec);
    }
  }
  try {
    open();
  } catch (const std::system_error&) {
    return false;
  }
  return true;
}

bool MetadataLogger::write(const llmfw::v1::Frame& frame) {
  if (!frame.has_capture()) {
    return true;
  }
  if (file_ == nullptr) {
    return false;
  }
  google::protobuf::util::JsonPrintOptions options;
  options.preserve_proto_field_names = true;
  std::string line;
  if (!google::protobuf::util::MessageToJsonString(toMetadataRecord(frame.capture(), cfg_, proxy_instance_id_), &line,
                                                   options)
           .ok()) {
    return false;
  }
  line.push_back('\n');

  if (written_ > 0 && written_ + line.size() > cfg_.rotate_bytes && !rotate()) {
    return false;
  }
  if (std::fwrite(line.data(), 1, line.size(), file_) != line.size() || std::fflush(file_) != 0) {
    return false;
  }
  written_ += line.size();
  return true;
}

void MetadataLogger::tick(std::chrono::steady_clock::time_point /*now*/) {
  if (file_ != nullptr) {
    return;
  }
  try {
    open();
  } catch (const std::system_error&) {
  }
}

void MetadataLogger::close() {
  if (file_ != nullptr) {
    std::fclose(file_);
    file_ = nullptr;
  }
}

}  // namespace llmfw
