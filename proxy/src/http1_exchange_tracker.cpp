#include "llmfw/http1_exchange_tracker.hpp"

#include <chrono>
#include <utility>

namespace llmfw {

namespace {

/// The wall-clock time, in Unix microseconds, at which steady time `at` happened.
std::int64_t unixMicros(Clock::time_point at) {
  const auto ago = std::chrono::duration_cast<std::chrono::system_clock::duration>(Clock::now() - at);
  return std::chrono::duration_cast<std::chrono::microseconds>((std::chrono::system_clock::now() - ago).time_since_epoch())
      .count();
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
      t_.finishFront(ExchangeOutcomeTag::kComplete);
      active_ = false;
    }
    t_.response_started_at_.reset();
  }

 private:
  Http1ExchangeTracker& t_;
  bool active_ = false;  ///< The response being parsed completes the front exchange.
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
  if (!request_started_at_) {
    request_started_at_ = at;
  }
  handle(request_parser_.feed(bytes));
}

void Http1ExchangeTracker::onUpstreamBytes(std::span<const std::uint8_t> bytes, Clock::time_point at) {
  if (!capturing_) {
    return;
  }
  response_chunk_at_ = at;
  if (!response_started_at_) {
    response_started_at_ = at;
  }
  handle(response_parser_.feed(bytes));
}

void Http1ExchangeTracker::onClosed(ExchangeOutcomeTag unfinished) {
  if (!capturing_) {
    return;
  }
  // A failure here means the close cut a message short, which `unfinished` describes.
  (void)response_parser_.finish();
  stop(unfinished);
}

void Http1ExchangeTracker::handle(const FeedResult& result) {
  if (result.status == FeedStatus::kError) {
    stop(ExchangeOutcomeTag::kParseError);
    if (sinks_.parse_error) {
      sinks_.parse_error();
    }
  } else if (result.status == FeedStatus::kUpgrade) {
    stop(ExchangeOutcomeTag::kUpgraded);
  }
}

void Http1ExchangeTracker::finishFront(ExchangeOutcomeTag outcome) {
  if (in_flight_.size() == 1) {
    request_open_ = false;
  }
  std::unique_ptr<ExchangeCaptureBuilder> builder = std::move(in_flight_.front().builder);
  in_flight_.pop_front();
  sinks_.push(builder->finish(outcome));
}

void Http1ExchangeTracker::stop(ExchangeOutcomeTag outcome) {
  capturing_ = false;
  while (!in_flight_.empty()) {
    finishFront(outcome);
  }
}

}  // namespace llmfw
