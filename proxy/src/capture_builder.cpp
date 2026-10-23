#include "llmfw/capture_builder.hpp"

#include <algorithm>
#include <cctype>
#include <string>

namespace llmfw {

namespace {

llmfw::v1::ClientPath toProto(ClientPathTag path) {
  switch (path) {
    case ClientPathTag::kUi: return llmfw::v1::CLIENT_PATH_UI;
    case ClientPathTag::kClaudeCode: return llmfw::v1::CLIENT_PATH_CLAUDE_CODE;
    case ClientPathTag::kVm: return llmfw::v1::CLIENT_PATH_VM;
    case ClientPathTag::kUnknown: break;
  }
  return llmfw::v1::CLIENT_PATH_UNKNOWN;
}

llmfw::v1::TunnelReason toProto(TunnelReasonTag reason) {
  switch (reason) {
    case TunnelReasonTag::kUnscopedHost: return llmfw::v1::TUNNEL_REASON_UNSCOPED_HOST;
    case TunnelReasonTag::kScopedNoCert: return llmfw::v1::TUNNEL_REASON_SCOPED_NO_CERT;
    case TunnelReasonTag::kUpstreamVerifyFailed: return llmfw::v1::TUNNEL_REASON_UPSTREAM_VERIFY_FAILED;
    case TunnelReasonTag::kClientTlsBreaker: return llmfw::v1::TUNNEL_REASON_CLIENT_TLS_BREAKER;
    case TunnelReasonTag::kNonTlsPort: return llmfw::v1::TUNNEL_REASON_NON_TLS_PORT;
    case TunnelReasonTag::kClientSentEarly: return llmfw::v1::TUNNEL_REASON_CLIENT_SENT_EARLY;
    case TunnelReasonTag::kNone: break;
  }
  return llmfw::v1::TUNNEL_REASON_UNSPECIFIED;
}

llmfw::v1::ExchangeOutcome toProto(ExchangeOutcomeTag outcome) {
  switch (outcome) {
    case ExchangeOutcomeTag::kComplete: return llmfw::v1::EXCHANGE_OUTCOME_COMPLETE;
    case ExchangeOutcomeTag::kClientAborted: return llmfw::v1::EXCHANGE_OUTCOME_CLIENT_ABORTED;
    case ExchangeOutcomeTag::kUpstreamAborted: return llmfw::v1::EXCHANGE_OUTCOME_UPSTREAM_ABORTED;
    case ExchangeOutcomeTag::kTimeout: return llmfw::v1::EXCHANGE_OUTCOME_TIMEOUT;
    case ExchangeOutcomeTag::kParseError: return llmfw::v1::EXCHANGE_OUTCOME_PARSE_ERROR;
    case ExchangeOutcomeTag::kUpgraded: return llmfw::v1::EXCHANGE_OUTCOME_UPGRADED;
  }
  return llmfw::v1::EXCHANGE_OUTCOME_UNSPECIFIED;
}

std::string lowerCase(std::string_view text) {
  std::string out(text);
  std::transform(out.begin(), out.end(), out.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  return out;
}

std::string httpVersion(const Http1Head& head) {
  return "HTTP/" + std::to_string(head.version_major) + "." + std::to_string(head.version_minor);
}

/// Copies the headers, redacting the values of `redact` (lower-cased names).
void copyHeaders(const Http1Head& head, const std::vector<std::string>& redact,
                 google::protobuf::RepeatedPtrField<llmfw::v1::Header>& out) {
  for (const auto& [name, value] : head.headers) {
    llmfw::v1::Header& header = *out.Add();
    header.set_name(name);
    if (std::find(redact.begin(), redact.end(), lowerCase(name)) != redact.end()) {
      header.set_redacted(true);
      header.set_original_value_length(static_cast<std::uint32_t>(value.size()));
    } else {
      header.set_value(value);
    }
  }
}

/// The first value of a header, matched ignoring case.
std::string_view headerValue(const Http1Head& head, std::string_view lower_name) {
  for (const auto& [name, value] : head.headers) {
    if (lowerCase(name) == lower_name) {
      return value;
    }
  }
  return {};
}

std::uint64_t nonNegativeMicros(std::chrono::microseconds value) {
  return static_cast<std::uint64_t>(std::max<std::int64_t>(0, value.count()));
}

/// A frame whose capture has its id, connection, client info and start time filled in.
std::unique_ptr<llmfw::v1::Frame> startCapture(const CaptureBuildContext& ctx, std::uint64_t connection_id,
                                               std::string_view connect_user_agent, std::int64_t start_unix_us) {
  auto frame = std::make_unique<llmfw::v1::Frame>();
  llmfw::v1::Capture& capture = *frame->mutable_capture();
  capture.set_capture_id(ctx.counters.nextCaptureId());
  capture.set_connection_id(connection_id);
  capture.set_exchange_index(0);

  llmfw::v1::ClientInfo& client = *capture.mutable_client();
  client.set_path(toProto(ctx.classifier.classify(connect_user_agent)));
  client.set_user_agent(std::string(connect_user_agent));
  client.set_connect_user_agent(std::string(connect_user_agent));

  capture.mutable_timings()->set_start_unix_us(start_unix_us);
  return frame;
}

}  // namespace

std::unique_ptr<llmfw::v1::Frame> buildTunnelCapture(const CaptureBuildContext& ctx, const TunnelObservation& tunnel) {
  auto frame = startCapture(ctx, tunnel.connection_id, tunnel.connect_user_agent, tunnel.start_unix_us);
  llmfw::v1::TunnelSummary& summary = *frame->mutable_capture()->mutable_tunnel();
  summary.set_host(std::string(tunnel.host));
  summary.set_port(tunnel.port);
  summary.set_reason(toProto(tunnel.reason));
  summary.set_bytes_client_to_server(tunnel.bytes_client_to_server);
  summary.set_bytes_server_to_client(tunnel.bytes_server_to_client);
  summary.set_duration_us(nonNegativeMicros(tunnel.duration));
  return frame;
}

std::unique_ptr<llmfw::v1::Frame> buildDecryptedCapture(const CaptureBuildContext& ctx,
                                                        const DecryptedObservation& connection) {
  auto frame = startCapture(ctx, connection.connection_id, connection.connect_user_agent, connection.start_unix_us);
  llmfw::v1::DecryptedConnection& summary = *frame->mutable_capture()->mutable_decrypted();
  summary.set_host(std::string(connection.host));
  summary.set_port(connection.port);
  summary.set_alpn(std::string(connection.alpn));
  summary.set_bytes_client_to_server(connection.bytes_client_to_server);
  summary.set_bytes_server_to_client(connection.bytes_server_to_client);
  summary.set_duration_us(nonNegativeMicros(connection.duration));
  summary.set_upstream_connect_us(nonNegativeMicros(connection.upstream_connect));
  summary.set_client_handshake_us(nonNegativeMicros(connection.client_handshake));
  return frame;
}

ExchangeCaptureBuilder::ExchangeCaptureBuilder(const CaptureBuildContext& ctx, const CaptureConfig& cfg,
                                               const ExchangeConnection& connection,
                                               std::uint32_t exchange_index, Clock::time_point started,
                                               std::int64_t started_unix_us)
    : ctx_(ctx),
      cfg_(cfg),
      connection_(connection),
      started_(started),
      frame_(std::make_unique<llmfw::v1::Frame>()) {
  llmfw::v1::Capture& capture = *frame_->mutable_capture();
  capture.set_connection_id(connection.connection_id);
  capture.set_exchange_index(exchange_index);
  llmfw::v1::Timings& timings = *capture.mutable_timings();
  timings.set_start_unix_us(started_unix_us);
  if (exchange_index == 0) {
    timings.set_upstream_connect_us(nonNegativeMicros(connection.upstream_connect));
    timings.set_client_tls_handshake_us(nonNegativeMicros(connection.client_handshake));
  }
  llmfw::v1::HttpExchange& http = *capture.mutable_http();
  http.set_connect_host(connection.connect_host);
  http.set_connect_port(connection.connect_port);
  http.set_negotiated_alpn(connection.alpn.empty() ? "http/1.1" : connection.alpn);
}

void ExchangeCaptureBuilder::setRequestHead(const Http1Head& head) {
  llmfw::v1::HttpRequest& request = *frame_->mutable_capture()->mutable_http()->mutable_request();
  request.set_method(head.method);
  request.set_host(lowerCase(headerValue(head, "host")));
  request.set_target(head.target);
  request.set_http_version(httpVersion(head));
  copyHeaders(head, cfg_.redact_headers, *request.mutable_headers());
  request_user_agent_ = std::string(headerValue(head, "user-agent"));
  head_request_ = head.method == "HEAD";
}

void ExchangeCaptureBuilder::markRequestComplete(Clock::time_point at) {
  frame_->mutable_capture()->mutable_timings()->set_request_complete_us(sinceStart(at));
}

void ExchangeCaptureBuilder::setResponseHead(const Http1Head& head, Clock::time_point at) {
  llmfw::v1::HttpResponse& response = *frame_->mutable_capture()->mutable_http()->mutable_response();
  response.set_status(head.status);
  response.set_reason(head.reason);
  response.set_http_version(httpVersion(head));
  copyHeaders(head, cfg_.redact_headers, *response.mutable_headers());
  frame_->mutable_capture()->mutable_timings()->set_response_first_byte_us(sinceStart(at));
}

void ExchangeCaptureBuilder::markResponseComplete(Clock::time_point at) {
  frame_->mutable_capture()->mutable_timings()->set_response_complete_us(sinceStart(at));
}

bool ExchangeCaptureBuilder::isHeadRequest() const { return head_request_; }

std::unique_ptr<llmfw::v1::Frame> ExchangeCaptureBuilder::finish(ExchangeOutcomeTag outcome) {
  llmfw::v1::Capture& capture = *frame_->mutable_capture();
  capture.set_capture_id(ctx_.counters.nextCaptureId());
  capture.mutable_http()->set_outcome(toProto(outcome));

  const std::string& user_agent = request_user_agent_.empty() ? connection_.connect_user_agent : request_user_agent_;
  ClientPathTag path = ctx_.classifier.classify(user_agent);
  if (path == ClientPathTag::kUnknown) {
    path = ctx_.classifier.classify(connection_.connect_user_agent);
  }
  llmfw::v1::ClientInfo& client = *capture.mutable_client();
  client.set_path(toProto(path));
  client.set_user_agent(user_agent);
  client.set_connect_user_agent(connection_.connect_user_agent);
  return std::move(frame_);
}

std::uint64_t ExchangeCaptureBuilder::sinceStart(Clock::time_point at) const {
  return nonNegativeMicros(std::chrono::duration_cast<std::chrono::microseconds>(at - started_));
}

std::size_t approximateFrameBytes(const llmfw::v1::Frame& frame) { return frame.ByteSizeLong(); }

}  // namespace llmfw
