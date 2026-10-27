#include <gtest/gtest.h>

#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

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
      {TunnelReasonTag::kClientSentEarly, llmfw::v1::TUNNEL_REASON_CLIENT_SENT_EARLY},
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

DecryptedObservation sampleDecrypted() {
  DecryptedObservation d;
  d.connection_id = 43;
  d.host = "api.anthropic.com";
  d.port = 443;
  d.alpn = "http/1.1";
  d.connect_user_agent = "";
  d.bytes_client_to_server = 5'000;
  d.bytes_server_to_client = 70'000;
  d.start_unix_us = 1'790'000'000'000'000;
  d.duration = std::chrono::microseconds(4'000'000);
  d.upstream_connect = std::chrono::microseconds(30'000);
  d.client_handshake = std::chrono::microseconds(2'000);
  return d;
}

TEST(BuildDecryptedCapture, CopiesConnectionMetadata) {
  const ClientClassifier classifier = desktopClassifier();
  ProxyCounters counters;
  const auto frame = buildDecryptedCapture({classifier, counters}, sampleDecrypted());
  const llmfw::v1::Capture& capture = frame->capture();
  EXPECT_EQ(capture.capture_id(), 1u);
  EXPECT_EQ(capture.connection_id(), 43u);
  EXPECT_EQ(capture.client().path(), llmfw::v1::CLIENT_PATH_UNKNOWN);
  EXPECT_EQ(capture.timings().start_unix_us(), 1'790'000'000'000'000);
  ASSERT_EQ(capture.payload_case(), llmfw::v1::Capture::kDecrypted);
  const llmfw::v1::DecryptedConnection& decrypted = capture.decrypted();
  EXPECT_EQ(decrypted.host(), "api.anthropic.com");
  EXPECT_EQ(decrypted.port(), 443u);
  EXPECT_EQ(decrypted.alpn(), "http/1.1");
  EXPECT_EQ(decrypted.bytes_client_to_server(), 5'000u);
  EXPECT_EQ(decrypted.bytes_server_to_client(), 70'000u);
  EXPECT_EQ(decrypted.duration_us(), 4'000'000u);
  EXPECT_EQ(decrypted.upstream_connect_us(), 30'000u);
  EXPECT_EQ(decrypted.client_handshake_us(), 2'000u);
}

TEST(BuildDecryptedCapture, ClassifiesTheConnectUserAgent) {
  const ClientClassifier classifier = desktopClassifier();
  ProxyCounters counters;
  DecryptedObservation d = sampleDecrypted();
  d.connect_user_agent = "Mozilla/5.0 Claude/2.9 Electron/38";
  EXPECT_EQ(buildDecryptedCapture({classifier, counters}, d)->capture().client().path(), llmfw::v1::CLIENT_PATH_UI);
}

TEST(BuildDecryptedCapture, PrefersTheUserAgentSentInsideTls) {
  const ClientClassifier classifier = desktopClassifier();
  ProxyCounters counters;
  DecryptedObservation d = sampleDecrypted();
  d.user_agent = "claude-cli/2.1 (external)";
  const auto frame = buildDecryptedCapture({classifier, counters}, d);
  EXPECT_EQ(frame->capture().client().path(), llmfw::v1::CLIENT_PATH_CLAUDE_CODE);
  EXPECT_EQ(frame->capture().client().user_agent(), "claude-cli/2.1 (external)");
  EXPECT_EQ(frame->capture().client().connect_user_agent(), "");
}

TEST(BuildDecryptedCapture, AnUnknownInnerUserAgentFallsBackToTheConnects) {
  const ClientClassifier classifier = desktopClassifier();
  ProxyCounters counters;
  DecryptedObservation d = sampleDecrypted();
  d.user_agent = "Bun/1.4";
  d.connect_user_agent = "Mozilla/5.0 Claude/2.9 Electron/38";
  const auto frame = buildDecryptedCapture({classifier, counters}, d);
  EXPECT_EQ(frame->capture().client().path(), llmfw::v1::CLIENT_PATH_UI);
  EXPECT_EQ(frame->capture().client().user_agent(), "Bun/1.4");
}

TEST(BuildDecryptedCapture, ClampsNegativeDurationsToZero) {
  const ClientClassifier classifier = desktopClassifier();
  ProxyCounters counters;
  DecryptedObservation d = sampleDecrypted();
  d.duration = std::chrono::microseconds(-1);
  d.upstream_connect = std::chrono::microseconds(-1);
  d.client_handshake = std::chrono::microseconds(-1);
  const auto frame = buildDecryptedCapture({classifier, counters}, d);
  const llmfw::v1::DecryptedConnection& decrypted = frame->capture().decrypted();
  EXPECT_EQ(decrypted.duration_us(), 0u);
  EXPECT_EQ(decrypted.upstream_connect_us(), 0u);
  EXPECT_EQ(decrypted.client_handshake_us(), 0u);
}

ExchangeConnection sampleConnection() {
  ExchangeConnection c;
  c.connection_id = 9;
  c.connect_host = "api.anthropic.com";
  c.connect_port = 443;
  c.upstream_connect = std::chrono::microseconds(40'000);
  c.client_handshake = std::chrono::microseconds(2'000);
  return c;
}

CaptureConfig captureConfig() {
  CaptureConfig cfg;
  cfg.request_body_cap_bytes = 4;
  cfg.response_body_cap_bytes = 8;
  cfg.redact_headers = {"authorization", "cookie"};
  return cfg;
}

Http1Head requestHead(std::string method = "POST") {
  Http1Head head;
  head.method = std::move(method);
  head.target = "/v1/messages?beta=true";
  head.headers = {{"Host", "API.Anthropic.com"},
                  {"User-Agent", "claude-cli/2.1.299 (external, cli)"},
                  {"AUTHORIZATION", "Bearer sk-secret"},
                  {"Content-Type", "application/json"}};
  return head;
}

Http1Head responseHead() {
  Http1Head head;
  head.status = 200;
  head.reason = "OK";
  head.headers = {{"Content-Type", "text/event-stream"}, {"set-cookie", "a=b"}};
  return head;
}

std::span<const std::uint8_t> bytesOf(std::string_view text) {
  return {reinterpret_cast<const std::uint8_t*>(text.data()), text.size()};
}

struct ExchangeFixture {
  ClientClassifier classifier = desktopClassifier();
  ProxyCounters counters;
  CaptureBuildContext ctx{classifier, counters};
  CaptureConfig cfg = captureConfig();
  ExchangeConnection connection = sampleConnection();
  Clock::time_point t0 = Clock::now();

  ExchangeCaptureBuilder builder(CaptureMode mode, std::uint32_t index = 0) {
    return {ctx, cfg, mode, connection, index, t0, 1'790'000'000'000'000};
  }
};

TEST(ExchangeCaptureBuilder, BuildsACompleteExchange) {
  ExchangeFixture f;
  ExchangeCaptureBuilder b = f.builder(CaptureMode::kMetadataOnly);
  b.setRequestHead(requestHead());
  b.appendRequestBody(bytesOf("{\"a\":1}"));
  b.markRequestComplete(f.t0 + std::chrono::milliseconds(1));
  b.setResponseHead(responseHead(), f.t0 + std::chrono::milliseconds(300));
  b.appendResponseBody(bytesOf("data: x\n\n"));
  b.markResponseComplete(f.t0 + std::chrono::milliseconds(900));
  const auto frame = b.finish(ExchangeOutcomeTag::kComplete);

  const llmfw::v1::Capture& capture = frame->capture();
  EXPECT_EQ(capture.capture_id(), 1u);
  EXPECT_EQ(capture.connection_id(), 9u);
  EXPECT_EQ(capture.exchange_index(), 0u);
  const llmfw::v1::HttpExchange& http = capture.http();
  EXPECT_EQ(http.connect_host(), "api.anthropic.com");
  EXPECT_EQ(http.connect_port(), 443u);
  EXPECT_EQ(http.negotiated_alpn(), "http/1.1");
  EXPECT_EQ(http.outcome(), llmfw::v1::EXCHANGE_OUTCOME_COMPLETE);
  EXPECT_EQ(http.request().method(), "POST");
  EXPECT_EQ(http.request().host(), "api.anthropic.com");
  EXPECT_EQ(http.request().target(), "/v1/messages?beta=true");
  EXPECT_EQ(http.request().http_version(), "HTTP/1.1");
  EXPECT_EQ(http.request().headers_size(), 4);
  EXPECT_EQ(http.response().status(), 200u);
  EXPECT_EQ(http.response().reason(), "OK");

  const llmfw::v1::Timings& timings = capture.timings();
  EXPECT_EQ(timings.start_unix_us(), 1'790'000'000'000'000);
  EXPECT_EQ(timings.request_complete_us(), 1'000u);
  EXPECT_EQ(timings.response_first_byte_us(), 300'000u);
  EXPECT_EQ(timings.response_complete_us(), 900'000u);
  EXPECT_EQ(timings.upstream_connect_us(), 40'000u);
  EXPECT_EQ(timings.client_tls_handshake_us(), 2'000u);
}

TEST(ExchangeCaptureBuilder, RedactsConfiguredHeadersIgnoringCase) {
  ExchangeFixture f;
  f.cfg.redact_headers.push_back("set-cookie");
  ExchangeCaptureBuilder b = f.builder(CaptureMode::kFull);
  b.setRequestHead(requestHead());
  b.setResponseHead(responseHead(), f.t0);
  const auto frame = b.finish(ExchangeOutcomeTag::kComplete);
  const llmfw::v1::Header& auth = frame->capture().http().request().headers(2);
  EXPECT_EQ(auth.name(), "AUTHORIZATION");
  EXPECT_TRUE(auth.redacted());
  EXPECT_EQ(auth.value(), "");
  EXPECT_EQ(auth.original_value_length(), std::string("Bearer sk-secret").size());
  EXPECT_FALSE(frame->capture().http().request().headers(3).redacted());
  EXPECT_TRUE(frame->capture().http().response().headers(1).redacted());
  EXPECT_EQ(frame->SerializeAsString().find("sk-secret"), std::string::npos);
}

TEST(ExchangeCaptureBuilder, MetadataOnlyKeepsBodySizesButNoBytes) {
  ExchangeFixture f;
  ExchangeCaptureBuilder b = f.builder(CaptureMode::kMetadataOnly);
  b.setRequestHead(requestHead());
  b.appendRequestBody(bytesOf("secret-prompt"));
  b.setResponseHead(responseHead(), f.t0);
  b.appendResponseBody(bytesOf("secret-reply"));
  const auto frame = b.finish(ExchangeOutcomeTag::kComplete);
  const llmfw::v1::HttpExchange& http = frame->capture().http();
  EXPECT_TRUE(http.request().body().omitted());
  EXPECT_EQ(http.request().body().total_bytes(), 13u);
  EXPECT_EQ(http.request().body().data(), "");
  EXPECT_TRUE(http.response().body().omitted());
  EXPECT_EQ(http.response().body().total_bytes(), 12u);
  EXPECT_EQ(frame->SerializeAsString().find("secret-"), std::string::npos);
}

TEST(ExchangeCaptureBuilder, FullModeCapsBodies) {
  ExchangeFixture f;
  ExchangeCaptureBuilder b = f.builder(CaptureMode::kFull);
  b.setRequestHead(requestHead());
  b.appendRequestBody(bytesOf("ab"));
  b.appendRequestBody(bytesOf("cdef"));
  b.setResponseHead(responseHead(), f.t0);
  b.appendResponseBody(bytesOf("12345678"));
  const auto frame = b.finish(ExchangeOutcomeTag::kComplete);
  const llmfw::v1::Body& request = frame->capture().http().request().body();
  EXPECT_FALSE(request.omitted());
  EXPECT_EQ(request.data(), "abcd");
  EXPECT_EQ(request.total_bytes(), 6u);
  EXPECT_TRUE(request.truncated());
  const llmfw::v1::Body& response = frame->capture().http().response().body();
  EXPECT_EQ(response.data(), "12345678");
  EXPECT_FALSE(response.truncated());
  EXPECT_EQ(f.counters.request_bodies_truncated.load(), 1u);
  EXPECT_EQ(f.counters.response_bodies_truncated.load(), 0u);
}

TEST(ExchangeCaptureBuilder, CountsATruncatedResponseBody) {
  ExchangeFixture f;
  ExchangeCaptureBuilder b = f.builder(CaptureMode::kFull);
  b.setRequestHead(requestHead());
  b.setResponseHead(responseHead(), f.t0);
  b.appendResponseBody(bytesOf(std::string(f.cfg.response_body_cap_bytes + 1, 'r')));
  (void)b.finish(ExchangeOutcomeTag::kComplete);
  EXPECT_EQ(f.counters.request_bodies_truncated.load(), 0u);
  EXPECT_EQ(f.counters.response_bodies_truncated.load(), 1u);
}

TEST(ExchangeCaptureBuilder, MetadataOnlyCountsNoTruncation) {
  ExchangeFixture f;
  ExchangeCaptureBuilder b = f.builder(CaptureMode::kMetadataOnly);
  b.setRequestHead(requestHead());
  b.appendRequestBody(bytesOf("abcdef"));
  (void)b.finish(ExchangeOutcomeTag::kComplete);
  EXPECT_EQ(f.counters.request_bodies_truncated.load(), 0u);
}

TEST(ExchangeCaptureBuilder, ClassifiesTheRequestUserAgent) {
  ExchangeFixture f;
  f.connection.connect_user_agent = "";
  ExchangeCaptureBuilder b = f.builder(CaptureMode::kMetadataOnly);
  b.setRequestHead(requestHead());
  const auto frame = b.finish(ExchangeOutcomeTag::kComplete);
  EXPECT_EQ(frame->capture().client().path(), llmfw::v1::CLIENT_PATH_CLAUDE_CODE);
  EXPECT_EQ(frame->capture().client().user_agent(), "claude-cli/2.1.299 (external, cli)");
  EXPECT_EQ(frame->capture().client().connect_user_agent(), "");
}

TEST(ExchangeCaptureBuilder, FallsBackToTheConnectUserAgent) {
  ExchangeFixture f;
  f.connection.connect_user_agent = "Mozilla/5.0 Claude/2.9 Electron/38";
  Http1Head without_agent = requestHead();
  without_agent.headers.erase(without_agent.headers.begin() + 1);
  ExchangeCaptureBuilder b = f.builder(CaptureMode::kMetadataOnly);
  b.setRequestHead(without_agent);
  auto frame = b.finish(ExchangeOutcomeTag::kComplete);
  EXPECT_EQ(frame->capture().client().path(), llmfw::v1::CLIENT_PATH_UI);
  EXPECT_EQ(frame->capture().client().user_agent(), "Mozilla/5.0 Claude/2.9 Electron/38");

  Http1Head unknown_agent = requestHead();
  unknown_agent.headers[1].second = "fetch/1.0";
  ExchangeCaptureBuilder b2 = f.builder(CaptureMode::kMetadataOnly);
  b2.setRequestHead(unknown_agent);
  frame = b2.finish(ExchangeOutcomeTag::kComplete);
  EXPECT_EQ(frame->capture().client().path(), llmfw::v1::CLIENT_PATH_UI);
  EXPECT_EQ(frame->capture().client().user_agent(), "fetch/1.0");
}

TEST(ExchangeCaptureBuilder, ConnectionTimingsOnlyOnTheFirstExchange) {
  ExchangeFixture f;
  ExchangeCaptureBuilder b = f.builder(CaptureMode::kMetadataOnly, 3);
  b.setRequestHead(requestHead());
  const auto frame = b.finish(ExchangeOutcomeTag::kComplete);
  EXPECT_EQ(frame->capture().exchange_index(), 3u);
  EXPECT_EQ(frame->capture().timings().upstream_connect_us(), 0u);
  EXPECT_EQ(frame->capture().timings().client_tls_handshake_us(), 0u);
}

TEST(ExchangeCaptureBuilder, AnExchangeEndedEarlyHasNoResponse) {
  ExchangeFixture f;
  ExchangeCaptureBuilder b = f.builder(CaptureMode::kMetadataOnly);
  b.setRequestHead(requestHead("HEAD"));
  EXPECT_TRUE(b.isHeadRequest());
  const auto frame = b.finish(ExchangeOutcomeTag::kUpstreamAborted);
  EXPECT_FALSE(frame->capture().http().has_response());
  EXPECT_EQ(frame->capture().http().outcome(), llmfw::v1::EXCHANGE_OUTCOME_UPSTREAM_ABORTED);
}

TEST(ExchangeCaptureBuilder, MapsEveryOutcome) {
  const std::vector<std::pair<ExchangeOutcomeTag, llmfw::v1::ExchangeOutcome>> cases{
      {ExchangeOutcomeTag::kComplete, llmfw::v1::EXCHANGE_OUTCOME_COMPLETE},
      {ExchangeOutcomeTag::kClientAborted, llmfw::v1::EXCHANGE_OUTCOME_CLIENT_ABORTED},
      {ExchangeOutcomeTag::kUpstreamAborted, llmfw::v1::EXCHANGE_OUTCOME_UPSTREAM_ABORTED},
      {ExchangeOutcomeTag::kTimeout, llmfw::v1::EXCHANGE_OUTCOME_TIMEOUT},
      {ExchangeOutcomeTag::kParseError, llmfw::v1::EXCHANGE_OUTCOME_PARSE_ERROR},
      {ExchangeOutcomeTag::kUpgraded, llmfw::v1::EXCHANGE_OUTCOME_UPGRADED}};
  for (const auto& [tag, expected] : cases) {
    ExchangeFixture f;
    EXPECT_EQ(f.builder(CaptureMode::kMetadataOnly).finish(tag)->capture().http().outcome(), expected);
  }
}

TEST(ApproximateFrameBytes, IsTheSerializedSize) {
  const ClientClassifier classifier = desktopClassifier();
  ProxyCounters counters;
  const auto frame = buildTunnelCapture({classifier, counters}, sampleTunnel());
  EXPECT_EQ(approximateFrameBytes(*frame), frame->SerializeAsString().size());
}


WebSocketConnection sampleWebSocket() {
  WebSocketConnection ws;
  ws.connection_id = 44;
  ws.exchange_index = 2;
  ws.upgrade_capture_id = 17;
  ws.host = "api.anthropic.com";
  ws.target = "/v1/sessions/ws?token=t";
  ws.negotiated_extensions = "permessage-deflate";
  ws.user_agent = "claude-cli/2";
  ws.connect_user_agent = "";
  return ws;
}

WsMessage sampleMessage() {
  WsMessage m;
  m.opcode = ws_opcode::kText;
  m.payload = {'h', 'i'};
  m.total_bytes = 5;
  m.truncated = true;
  m.compressed = true;
  return m;
}

TEST(BuildWebSocketCapture, CopiesTheMessageAndItsConnection) {
  const ClientClassifier classifier = desktopClassifier();
  ProxyCounters counters;
  const auto frame = buildWebSocketCapture({classifier, counters}, CaptureMode::kFull, sampleWebSocket(),
                                           WsSender::kServer, 3, sampleMessage(), 1'790'000'000'000'000);
  const llmfw::v1::Capture& capture = frame->capture();
  EXPECT_EQ(capture.capture_id(), 1u);
  EXPECT_EQ(capture.connection_id(), 44u);
  EXPECT_EQ(capture.exchange_index(), 2u);
  EXPECT_EQ(capture.timings().start_unix_us(), 1'790'000'000'000'000);
  EXPECT_EQ(capture.client().path(), llmfw::v1::CLIENT_PATH_CLAUDE_CODE);
  ASSERT_EQ(capture.payload_case(), llmfw::v1::Capture::kWebsocket);
  const llmfw::v1::WebSocketMessage& ws = capture.websocket();
  EXPECT_EQ(ws.upgrade_capture_id(), 17u);
  EXPECT_EQ(ws.host(), "api.anthropic.com");
  EXPECT_EQ(ws.target(), "/v1/sessions/ws?token=t");
  EXPECT_EQ(ws.negotiated_extensions(), "permessage-deflate");
  EXPECT_EQ(ws.direction(), llmfw::v1::DIRECTION_SERVER_TO_CLIENT);
  EXPECT_EQ(ws.opcode(), llmfw::v1::WS_OPCODE_TEXT);
  EXPECT_EQ(ws.message_index(), 3u);
  EXPECT_EQ(ws.payload(), "hi");
  EXPECT_EQ(ws.total_bytes(), 5u);
  EXPECT_TRUE(ws.truncated());
  EXPECT_TRUE(ws.compressed());
  EXPECT_FALSE(ws.omitted());
  EXPECT_EQ(counters.ws_messages_truncated.load(), 1u);
}

TEST(BuildWebSocketCapture, MetadataOnlyOmitsThePayload) {
  const ClientClassifier classifier = desktopClassifier();
  ProxyCounters counters;
  const auto frame = buildWebSocketCapture({classifier, counters}, CaptureMode::kMetadataOnly, sampleWebSocket(),
                                           WsSender::kClient, 0, sampleMessage(), 0);
  const llmfw::v1::WebSocketMessage& ws = frame->capture().websocket();
  EXPECT_EQ(ws.direction(), llmfw::v1::DIRECTION_CLIENT_TO_SERVER);
  EXPECT_TRUE(ws.omitted());
  EXPECT_TRUE(ws.payload().empty());
  EXPECT_FALSE(ws.truncated());
  EXPECT_EQ(ws.total_bytes(), 5u);
  EXPECT_EQ(counters.ws_messages_truncated.load(), 0u);
}

TEST(BuildWebSocketCapture, MapsEveryOpcode) {
  const ClientClassifier classifier = desktopClassifier();
  ProxyCounters counters;
  const std::vector<std::pair<std::uint8_t, llmfw::v1::WsOpcode>> opcodes = {
      {ws_opcode::kText, llmfw::v1::WS_OPCODE_TEXT},   {ws_opcode::kBinary, llmfw::v1::WS_OPCODE_BINARY},
      {ws_opcode::kClose, llmfw::v1::WS_OPCODE_CLOSE}, {ws_opcode::kPing, llmfw::v1::WS_OPCODE_PING},
      {ws_opcode::kPong, llmfw::v1::WS_OPCODE_PONG},
  };
  for (const auto& [opcode, expected] : opcodes) {
    WsMessage m;
    m.opcode = opcode;
    const auto frame = buildWebSocketCapture({classifier, counters}, CaptureMode::kFull, sampleWebSocket(),
                                             WsSender::kServer, 0, std::move(m), 0);
    EXPECT_EQ(frame->capture().websocket().opcode(), expected) << int{opcode};
  }
}

TEST(BuildWebSocketCapture, AnUnknownUpgradeUserAgentFallsBackToTheConnects) {
  const ClientClassifier classifier = desktopClassifier();
  ProxyCounters counters;
  WebSocketConnection ws = sampleWebSocket();
  ws.user_agent = "";
  ws.connect_user_agent = "Mozilla/5.0 Electron/38";
  const auto frame = buildWebSocketCapture({classifier, counters}, CaptureMode::kFull, ws, WsSender::kClient, 0,
                                           sampleMessage(), 0);
  EXPECT_EQ(frame->capture().client().path(), llmfw::v1::CLIENT_PATH_UI);
  EXPECT_EQ(frame->capture().client().user_agent(), "Mozilla/5.0 Electron/38");
}

}  // namespace
}  // namespace llmfw
