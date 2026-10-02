#pragma once
// The sink for metadata_only mode: one JSON line per capture, using the protobuf JSON
// mapping of llmfw.v1.MetadataRecord with proto field names. It never writes bodies
// or header values outside the allowlist.

#include <chrono>
#include <cstddef>
#include <cstdio>
#include <string>

#include "llmfw/capture_sink.hpp"
#include "llmfw/config.hpp"

namespace llmfw {

/// Pure conversion from a Capture to its metadata record.
///   - Every capture: ids, kind ("tunnel", "http", "websocket", or "" if no payload),
///     client path, timings, and the User-Agent if "user-agent" is in
///     cfg.logged_header_values.
///   - Tunnel: host, tunnel_reason, request_bytes / response_bytes (bytes each way)
///     and tunnel_duration_us.
/// HTTP and WebSocket captures are not produced yet, so for them the record holds only
/// the fields every capture gets. Body data is never read.
[[nodiscard]] llmfw::v1::MetadataRecord toMetadataRecord(const llmfw::v1::Capture& capture,
                                                         const MetadataLogConfig& cfg,
                                                         const std::string& proxy_instance_id);

/// Appends records to cfg.path.
///   - Missing parent directories are created with mode 0700. Existing ones are left as they are.
///   - The file is opened with O_APPEND|O_NOFOLLOW and forced to mode 0600, so a
///     symlink at the path is refused rather than followed.
///   - Each line is flushed as it is written.
///   - Before a line would take the file past rotate_bytes, the file is rotated:
///     path -> path.1 -> ... -> path.<keep_files>, and the oldest is deleted. With
///     keep_files 0 the full file is deleted. A single line longer than rotate_bytes
///     still gets written, alone in its file. If a rename fails, the current file
///     keeps growing instead.
class MetadataLogger final : public FrameSink {
 public:
  /// @throws std::system_error if a directory cannot be created or the file cannot be opened.
  MetadataLogger(MetadataLogConfig cfg, std::string proxy_instance_id);
  ~MetadataLogger() override;
  MetadataLogger(const MetadataLogger&) = delete;
  MetadataLogger& operator=(const MetadataLogger&) = delete;

  /// Writes one record for a capture frame. Other frames (hello, stats) are skipped
  /// and return true. Returns false only on an I/O error: a failed write, or no file
  /// could be reopened after rotating.
  [[nodiscard]] bool write(const llmfw::v1::Frame& frame) override;
  /// Retries opening the file if a rotation left none open.
  void tick(std::chrono::steady_clock::time_point now) override;
  void close() override;

 private:
  void open();
  /// Returns whether a file is open afterwards.
  [[nodiscard]] bool rotate();

  MetadataLogConfig cfg_;
  std::string proxy_instance_id_;
  std::FILE* file_ = nullptr;
  std::size_t written_ = 0;  ///< Size of the current file, including what existed before opening.
};

}  // namespace llmfw
