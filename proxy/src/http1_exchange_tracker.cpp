#include "llmfw/http1_exchange_tracker.hpp"

#include <algorithm>
#include <cctype>
#include <string>
#include <string_view>
#include <utility>

namespace llmfw {

namespace {

bool equalsIgnoreCase(std::string_view a, std::string_view b) {
  return a.size() == b.size() && std::equal(a.begin(), a.end(), b.begin(), [](char x, char y) {
           return std::tolower(static_cast<unsigned char>(x)) == std::tolower(static_cast<unsigned char>(y));
         });
}

/// Whether the Upgrade header names websocket, which it does as a single token in practice.
bool asksForWebSocket(const Http1Head& head) {
  for (const auto& [name, value] : head.headers) {
    if (equalsIgnoreCase(name, "upgrade") && equalsIgnoreCase(value, "websocket")) {
      return true;
    }
  }
  return false;
}

std::string headerValue(const google::protobuf::RepeatedPtrField<llmfw::v1::Header>& headers,
                        std::string_view name) {
  for (const llmfw::v1::Header& header : headers) {
    if (equalsIgnoreCase(header.name(), name)) {
      return header.value();
    }
  }
  return {};
}

}  // namespace

class Http1ExchangeTracker::RequestEvents final : public Http1Events {
 public:
  explicit RequestEvents(Http1ExchangeTracker& tracker) : t_(tracker) {}

  void onHead(const Http1Head& head) override {
    const Clock::time_point started = t_.request_started_at_.value_or(t_.request_chunk_at_);
    Exchange exchange;
    exchange.builder = std::make_unique<ExchangeCaptureBuilder>(t_.ctx_, t_.cfg_, t_.mode_, t_.connection_,
                                                                t_.next_exchange_index_++, started, unixMicros(started));
    exchange.builder->setRequestHead(head);
    exchange.websocket = head.upgrade && asksForWebSocket(head);
    if (t_.client_user_agent_.empty()) {
      t_.client_user_agent_ = exchange.builder->requestUserAgent();
    }
    t_.response_parser_.expectResponse(exchange.builder->isHeadRequest());
    t_.in_flight_.push_back(std::move(exchange));
    t_.request_open_ = true;
  }

  void onBody(std::span<const std::uint8_t> bytes) override {
    if (t_.request_open_) {
      t_.in_flight_.back().builder->appendRequestBody(bytes);
    }
  }

  void onMessageComplete() override {
    if (t_.request_open_) {
      t_.in_flight_.back().builder->markRequestComplete(t_.request_chunk_at_);
      t_.in_flight_.back().request_complete = true;
      t_.request_open_ = false;
    }
    t_.request_started_at_.reset();
  }

 private:
  Http1ExchangeTracker& t_;
};

class Http1ExchangeTracker::ResponseEvents final : public Http1Events {
 public:
  explicit ResponseEvents(Http1ExchangeTracker& tracker) : t_(tracker) {}

  void onHead(const Http1Head& head) override {
    const bool interim = head.status < 200 && head.status != 101;
    active_ = !interim && !t_.in_flight_.empty() && !t_.in_flight_.front().response_started;
    switching_ = head.status == 101;
    // While an upgrade waits, its request is the only one in flight, so this answers it.
    if (t_.upgrade_pending_ && active_ && !switching_) {
      t_.resume_requests_ = true;
    }
    if (active_) {
      t_.in_flight_.front().builder->setResponseHead(head, t_.response_started_at_.value_or(t_.response_chunk_at_));
      t_.in_flight_.front().response_started = true;
    }
  }

  void onBody(std::span<const std::uint8_t> bytes) override {
    if (active_) {
      t_.in_flight_.front().builder->appendResponseBody(bytes);
    }
  }

  void onMessageComplete() override {
    if (active_) {
      t_.in_flight_.front().builder->markResponseComplete(t_.response_chunk_at_);
      t_.finishFront(switching_ ? ExchangeOutcomeTag::kUpgraded : ExchangeOutcomeTag::kComplete);
      active_ = false;
    }
    t_.response_started_at_.reset();
  }

 private:
  Http1ExchangeTracker& t_;
  bool active_ = false;     ///< The response being parsed completes the front exchange.
  bool switching_ = false;  ///< The response being parsed is a 101.
};

Http1ExchangeTracker::Http1ExchangeTracker(const CaptureBuildContext& ctx, const CaptureConfig& cfg, CaptureMode mode,
                                           const ExchangeConnection& connection, ExchangeSinks sinks)
    : ctx_(ctx),
      cfg_(cfg),
      mode_(mode),
      connection_(connection),
      sinks_(std::move(sinks)),
      request_events_(std::make_unique<RequestEvents>(*this)),
      response_events_(std::make_unique<ResponseEvents>(*this)),
      request_parser_(Http1Mode::kRequest, *request_events_),
      response_parser_(Http1Mode::kResponse, *response_events_) {}

Http1ExchangeTracker::~Http1ExchangeTracker() = default;

void Http1ExchangeTracker::onClientBytes(std::span<const std::uint8_t> bytes, Clock::time_point at) {
  if (!capturing_) {
    return;
  }
  request_chunk_at_ = at;
  if (upgrade_pending_) {
    if (held_.size() + bytes.size() > kMaxHeldUpgradeBytes) {
      failParse();
      return;
    }
    held_.insert(held_.end(), bytes.begin(), bytes.end());
    return;
  }
  if (!request_started_at_) {
    request_started_at_ = at;
  }
  feedRequests(bytes);
}

void Http1ExchangeTracker::feedRequests(std::span<const std::uint8_t> bytes) {
  const FeedResult result = request_parser_.feed(bytes);
  if (result.status != FeedStatus::kUpgrade) {
    handle(result);
    return;
  }
  upgrade_pending_ = true;
  const std::span<const std::uint8_t> rest = bytes.subspan(result.consumed);
  held_.assign(rest.begin(), rest.end());
}

void Http1ExchangeTracker::onUpstreamBytes(std::span<const std::uint8_t> bytes, Clock::time_point at) {
  if (!capturing_) {
    return;
  }
  response_chunk_at_ = at;
  if (!response_started_at_) {
    response_started_at_ = at;
  }
  const FeedResult result = response_parser_.feed(bytes);
  handle(result);
  if (result.status == FeedStatus::kUpgrade && upgrade_ && sinks_.upgraded) {
    const std::span<const std::uint8_t> rest = bytes.subspan(result.consumed);
    UpgradeHandoff handoff{std::move(*upgrade_), std::move(held_), request_chunk_at_, {rest.begin(), rest.end()}, at};
    upgrade_.reset();
    held_.clear();
    sinks_.upgraded(std::move(handoff));
    return;
  }
  if (capturing_ && resume_requests_) {
    resume_requests_ = false;
    upgrade_pending_ = false;
    request_parser_.resumeAfterRejectedUpgrade();
    const std::vector<std::uint8_t> held = std::move(held_);
    held_.clear();
    if (!held.empty()) {
      request_started_at_ = request_chunk_at_;
      feedRequests(held);
    }
  }
}

void Http1ExchangeTracker::onClosed(ExchangeOutcomeTag unfinished) {
  if (!capturing_) {
    return;
  }
  // A failure here means the close cut a message short, which `unfinished` describes.
  (void)response_parser_.finish();
  stop(unfinished);
}

std::string Http1ExchangeTracker::clientUserAgent() const { return client_user_agent_; }

void Http1ExchangeTracker::handle(const FeedResult& result) {
  if (result.status == FeedStatus::kError) {
    failParse();
  } else if (result.status == FeedStatus::kUpgrade) {
    // A 101 has already pushed its exchange; whatever is left cannot be HTTP.
    stop(ExchangeOutcomeTag::kUpgraded);
  }
}

void Http1ExchangeTracker::failParse() {
  stop(ExchangeOutcomeTag::kParseError);
  if (sinks_.parse_error) {
    sinks_.parse_error();
  }
}

void Http1ExchangeTracker::finishFront(ExchangeOutcomeTag outcome) {
  if (in_flight_.size() == 1) {
    request_open_ = false;
  }
  std::unique_ptr<ExchangeCaptureBuilder> builder = std::move(in_flight_.front().builder);
  const bool websocket = in_flight_.front().websocket;
  in_flight_.pop_front();
  std::unique_ptr<llmfw::v1::Frame> frame = builder->finish(outcome);
  if (outcome == ExchangeOutcomeTag::kUpgraded && websocket) {
    const llmfw::v1::Capture& capture = frame->capture();
    const llmfw::v1::HttpExchange& http = capture.http();
    WebSocketConnection& ws = upgrade_.emplace();
    ws.connection_id = capture.connection_id();
    ws.exchange_index = capture.exchange_index();
    ws.upgrade_capture_id = capture.capture_id();
    ws.host = http.request().host().empty() ? connection_.connect_host : http.request().host();
    ws.target = http.request().target();
    ws.negotiated_extensions = headerValue(http.response().headers(), "sec-websocket-extensions");
    ws.user_agent = capture.client().user_agent();
    ws.connect_user_agent = connection_.connect_user_agent;
  }
  sinks_.push(std::move(frame));
}

void Http1ExchangeTracker::stop(ExchangeOutcomeTag outcome) {
  capturing_ = false;
  while (!in_flight_.empty()) {
    finishFront(outcome);
  }
}

}  // namespace llmfw
