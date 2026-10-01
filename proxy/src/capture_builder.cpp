#include "llmfw/capture_builder.hpp"

#include <algorithm>
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
    case TunnelReasonTag::kNone: break;
  }
  return llmfw::v1::TUNNEL_REASON_UNSPECIFIED;
}

}  // namespace

std::unique_ptr<llmfw::v1::Frame> buildTunnelCapture(const CaptureBuildContext& ctx, const TunnelObservation& tunnel) {
  auto frame = std::make_unique<llmfw::v1::Frame>();
  llmfw::v1::Capture& capture = *frame->mutable_capture();
  capture.set_capture_id(ctx.counters.nextCaptureId());
  capture.set_connection_id(tunnel.connection_id);
  capture.set_exchange_index(0);

  llmfw::v1::ClientInfo& client = *capture.mutable_client();
  client.set_path(toProto(ctx.classifier.classify(tunnel.connect_user_agent)));
  client.set_user_agent(std::string(tunnel.connect_user_agent));
  client.set_connect_user_agent(std::string(tunnel.connect_user_agent));

  capture.mutable_timings()->set_start_unix_us(tunnel.start_unix_us);

  llmfw::v1::TunnelSummary& summary = *capture.mutable_tunnel();
  summary.set_host(std::string(tunnel.host));
  summary.set_port(tunnel.port);
  summary.set_reason(toProto(tunnel.reason));
  summary.set_bytes_client_to_server(tunnel.bytes_client_to_server);
  summary.set_bytes_server_to_client(tunnel.bytes_server_to_client);
  summary.set_duration_us(static_cast<std::uint64_t>(std::max<std::int64_t>(0, tunnel.duration.count())));
  return frame;
}

std::size_t approximateFrameBytes(const llmfw::v1::Frame& frame) { return frame.ByteSizeLong(); }

}  // namespace llmfw
