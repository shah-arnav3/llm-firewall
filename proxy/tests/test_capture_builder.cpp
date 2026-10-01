#include <gtest/gtest.h>

#include "llmfw/capture_builder.hpp"

namespace llmfw {
namespace {

ClientClassifier desktopClassifier() {
  return ClientClassifier({{ClientPathTag::kClaudeCode, {"claude-cli/"}}, {ClientPathTag::kUi, {"Electron/"}}});
}

TunnelObservation sampleTunnel() {
  TunnelObservation t;
  t.connection_id = 42;
  t.host = "claude.ai";
  t.port = 443;
  t.reason = TunnelReasonTag::kScopedNoCert;
  t.connect_user_agent = "Mozilla/5.0 Claude/2.9 Electron/38";
  t.bytes_client_to_server = 1200;
  t.bytes_server_to_client = 98'000;
  t.start_unix_us = 1'790'000'000'000'000;
  t.duration = std::chrono::microseconds(2'500'000);
  return t;
}

TEST(BuildTunnelCapture, CopiesTunnelMetadata) {
  const ClientClassifier classifier = desktopClassifier();
  ProxyCounters counters;
  const auto frame = buildTunnelCapture({classifier, counters}, sampleTunnel());

  ASSERT_TRUE(frame->has_capture());
  const llmfw::v1::Capture& capture = frame->capture();
  EXPECT_EQ(capture.capture_id(), 1u);
  EXPECT_EQ(capture.connection_id(), 42u);
  EXPECT_EQ(capture.exchange_index(), 0u);
  EXPECT_EQ(capture.client().path(), llmfw::v1::CLIENT_PATH_UI);
  EXPECT_EQ(capture.client().user_agent(), "Mozilla/5.0 Claude/2.9 Electron/38");
  EXPECT_EQ(capture.client().connect_user_agent(), "Mozilla/5.0 Claude/2.9 Electron/38");
  EXPECT_EQ(capture.timings().start_unix_us(), 1'790'000'000'000'000);

  ASSERT_TRUE(capture.has_tunnel());
  const llmfw::v1::TunnelSummary& tunnel = capture.tunnel();
  EXPECT_EQ(tunnel.host(), "claude.ai");
  EXPECT_EQ(tunnel.port(), 443u);
  EXPECT_EQ(tunnel.reason(), llmfw::v1::TUNNEL_REASON_SCOPED_NO_CERT);
  EXPECT_EQ(tunnel.bytes_client_to_server(), 1200u);
  EXPECT_EQ(tunnel.bytes_server_to_client(), 98'000u);
  EXPECT_EQ(tunnel.duration_us(), 2'500'000u);
}

TEST(BuildTunnelCapture, ContainsNoPayloadFields) {
  const ClientClassifier classifier = desktopClassifier();
  ProxyCounters counters;
  const auto frame = buildTunnelCapture({classifier, counters}, sampleTunnel());
  EXPECT_FALSE(frame->capture().has_http());
  EXPECT_FALSE(frame->capture().has_websocket());
  EXPECT_EQ(frame->capture().payload_case(), llmfw::v1::Capture::kTunnel);
}

TEST(BuildTunnelCapture, MapsEveryReason) {
  const ClientClassifier classifier = desktopClassifier();
  ProxyCounters counters;
  const std::pair<TunnelReasonTag, llmfw::v1::TunnelReason> cases[] = {
      {TunnelReasonTag::kUnscopedHost, llmfw::v1::TUNNEL_REASON_UNSCOPED_HOST},
      {TunnelReasonTag::kScopedNoCert, llmfw::v1::TUNNEL_REASON_SCOPED_NO_CERT},
      {TunnelReasonTag::kUpstreamVerifyFailed, llmfw::v1::TUNNEL_REASON_UPSTREAM_VERIFY_FAILED},
      {TunnelReasonTag::kClientTlsBreaker, llmfw::v1::TUNNEL_REASON_CLIENT_TLS_BREAKER},
      {TunnelReasonTag::kNonTlsPort, llmfw::v1::TUNNEL_REASON_NON_TLS_PORT},
  };
  for (const auto& [tag, expected] : cases) {
    TunnelObservation t = sampleTunnel();
    t.reason = tag;
    EXPECT_EQ(buildTunnelCapture({classifier, counters}, t)->capture().tunnel().reason(), expected);
  }
}

TEST(BuildTunnelCapture, AssignsMonotonicCaptureIds) {
  const ClientClassifier classifier = desktopClassifier();
  ProxyCounters counters;
  for (std::uint64_t expected = 1; expected <= 5; ++expected) {
    EXPECT_EQ(buildTunnelCapture({classifier, counters}, sampleTunnel())->capture().capture_id(), expected);
  }
  EXPECT_EQ(counters.captures_created.load(), 5u);
}

TEST(BuildTunnelCapture, UnknownClientWithoutUserAgent) {
  const ClientClassifier classifier = desktopClassifier();
  ProxyCounters counters;
  TunnelObservation t = sampleTunnel();
  t.connect_user_agent = "";
  EXPECT_EQ(buildTunnelCapture({classifier, counters}, t)->capture().client().path(), llmfw::v1::CLIENT_PATH_UNKNOWN);
}

TEST(ApproximateFrameBytes, IsTheSerializedSize) {
  const ClientClassifier classifier = desktopClassifier();
  ProxyCounters counters;
  const auto frame = buildTunnelCapture({classifier, counters}, sampleTunnel());
  EXPECT_EQ(approximateFrameBytes(*frame), frame->SerializeAsString().size());
}

}  // namespace
}  // namespace llmfw
