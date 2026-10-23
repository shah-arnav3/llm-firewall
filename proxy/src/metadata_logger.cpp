#include "llmfw/metadata_logger.hpp"

#include <algorithm>
#include <cctype>
#include <string_view>
#include <vector>
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

/// The parameter names of a query string, in order, without their values.
std::vector<std::string> queryKeys(std::string_view query) {
  std::vector<std::string> keys;
  while (!query.empty()) {
    const std::size_t end = query.find('&');
    const std::string_view pair = query.substr(0, end);
    const std::string_view key = pair.substr(0, pair.find('='));
    if (!key.empty()) {
      keys.emplace_back(key);
    }
    if (end == std::string_view::npos) {
      break;
    }
    query.remove_prefix(end + 1);
  }
  return keys;
}

bool isContentType(const llmfw::v1::Header& header) {
  return !header.redacted() && header.name().size() == 12 &&
         std::equal(header.name().begin(), header.name().end(), "content-type",
                    [](char a, char b) { return std::tolower(static_cast<unsigned char>(a)) == b; });
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
    case llmfw::v1::Capture::kDecrypted: {
      const llmfw::v1::DecryptedConnection& decrypted = capture.decrypted();
      record.set_kind("decrypted");
      record.set_host(decrypted.host());
      record.set_alpn(decrypted.alpn());
      record.set_request_bytes(decrypted.bytes_client_to_server());
      record.set_response_bytes(decrypted.bytes_server_to_client());
      record.set_connection_duration_us(decrypted.duration_us());
      record.set_upstream_connect_us(decrypted.upstream_connect_us());
      record.set_client_handshake_us(decrypted.client_handshake_us());
      break;
    }
    case llmfw::v1::Capture::kHttp: {
      const llmfw::v1::HttpExchange& http = capture.http();
      record.set_kind("http");
      record.set_host(http.request().host().empty() ? http.connect_host() : http.request().host());
      record.set_alpn(http.negotiated_alpn());
      record.set_method(http.request().method());
      const std::string_view target = http.request().target();
      const std::size_t query = target.find('?');
      record.set_path(std::string(target.substr(0, query)));
      if (query != std::string_view::npos) {
        for (const std::string& key : queryKeys(target.substr(query + 1))) {
          record.add_query_keys(key);
        }
      }
      record.set_status(http.response().status());
      const bool content_type_allowed = std::find(allowed.begin(), allowed.end(), "content-type") != allowed.end();
      for (const llmfw::v1::Header& header : http.request().headers()) {
        record.add_request_header_names(header.name());
        if (content_type_allowed && record.request_content_type().empty() && isContentType(header)) {
          record.set_request_content_type(header.value());
        }
      }
      for (const llmfw::v1::Header& header : http.response().headers()) {
        record.add_response_header_names(header.name());
        if (content_type_allowed && record.response_content_type().empty() && isContentType(header)) {
          record.set_response_content_type(header.value());
        }
      }
      record.set_request_bytes(http.request().body().total_bytes());
      record.set_response_bytes(http.response().body().total_bytes());
      record.set_outcome(http.outcome());
      break;
    }
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
