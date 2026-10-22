#include "llmfw/http1_parser.hpp"

#include <deque>
#include <exception>

#include <llhttp.h>

namespace llmfw {

namespace {

enum class State { kParsing, kUpgraded, kFailed };

}  // namespace

struct Http1Parser::Impl {
  Impl(Http1Mode mode, Http1Events& events, Http1Limits limits) : mode(mode), events(events), limits(limits) {
    llhttp_settings_init(&settings);
    settings.on_message_begin = onMessageBegin;
    settings.on_url = onUrl;
    settings.on_status = onStatus;
    settings.on_header_field = onHeaderField;
    settings.on_header_value = onHeaderValue;
    settings.on_header_value_complete = onHeaderValueComplete;
    settings.on_headers_complete = onHeadersComplete;
    settings.on_body = onBody;
    settings.on_message_complete = onMessageComplete;
    llhttp_init(&parser, mode == Http1Mode::kRequest ? HTTP_REQUEST : HTTP_RESPONSE, &settings);
    parser.data = this;
  }

  static Impl& of(llhttp_t* p) { return *static_cast<Impl*>(p->data); }

  /// Records why a callback stopped the parse. llhttp replaces its own reason when a
  /// callback fails, so ours is kept here. Returns the error for data callbacks.
  int fail(const char* reason) {
    callback_error = reason;
    return HPE_USER;
  }

  /// Adds `length` head bytes, failing once the head exceeds the limit.
  int countHead(std::size_t length) {
    head_bytes += length;
    return head_bytes > limits.max_head_bytes ? fail("head exceeds max_head_bytes") : HPE_OK;
  }

  static int onMessageBegin(llhttp_t* p) {
    Impl& self = of(p);
    self.head = Http1Head{};
    self.head_bytes = 0;
    self.field_done = false;
    return HPE_OK;
  }

  static int onUrl(llhttp_t* p, const char* at, std::size_t length) {
    Impl& self = of(p);
    self.head.target.append(at, length);
    return self.countHead(length);
  }

  static int onStatus(llhttp_t* p, const char* at, std::size_t length) {
    Impl& self = of(p);
    self.head.reason.append(at, length);
    return self.countHead(length);
  }

  static int onHeaderField(llhttp_t* p, const char* at, std::size_t length) {
    Impl& self = of(p);
    // llhttp may deliver one name in several pieces; a new header starts only after
    // the previous value is complete.
    if (self.head.headers.empty() || self.field_done) {
      if (self.head.headers.size() >= self.limits.max_headers) {
        return self.fail("too many headers");
      }
      self.head.headers.emplace_back();
      self.field_done = false;
    }
    self.head.headers.back().first.append(at, length);
    return self.countHead(length);
  }

  static int onHeaderValue(llhttp_t* p, const char* at, std::size_t length) {
    Impl& self = of(p);
    self.head.headers.back().second.append(at, length);
    return self.countHead(length);
  }

  static int onHeaderValueComplete(llhttp_t* p) {
    of(p).field_done = true;
    return HPE_OK;
  }

  static int onHeadersComplete(llhttp_t* p) {
    Impl& self = of(p);
    Http1Head& head = self.head;
    if (self.mode == Http1Mode::kRequest) {
      head.method = llhttp_method_name(static_cast<llhttp_method_t>(p->method));
      self.head_bytes += head.method.size();
    } else {
      head.status = p->status_code;
    }
    if (self.head_bytes > self.limits.max_head_bytes) {
      self.fail("head exceeds max_head_bytes");
      return -1;
    }
    head.version_major = p->http_major;
    head.version_minor = p->http_minor;
    head.keep_alive = llhttp_should_keep_alive(p) != 0;
    head.upgrade = p->upgrade != 0;
    if ((p->flags & F_CONTENT_LENGTH) != 0) {
      head.content_length = p->content_length;
    }
    head.chunked = (p->flags & F_CHUNKED) != 0;

    // A 1xx other than 101 is an interim response: the request it answers is still waiting.
    bool skip_body = false;
    if (self.mode == Http1Mode::kResponse && (head.status >= 200 || head.status == 101)) {
      if (!self.head_requests.empty()) {
        skip_body = self.head_requests.front() && head.status != 101;
        self.head_requests.pop_front();
      }
    }
    try {
      self.events.onHead(head);
    } catch (const std::exception&) {
      self.fail("event handler threw");
      return -1;
    }
    return skip_body ? 1 : 0;
  }

  static int onBody(llhttp_t* p, const char* at, std::size_t length) {
    Impl& self = of(p);
    try {
      self.events.onBody({reinterpret_cast<const std::uint8_t*>(at), length});
    } catch (const std::exception&) {
      return self.fail("event handler threw");
    }
    return HPE_OK;
  }

  static int onMessageComplete(llhttp_t* p) {
    Impl& self = of(p);
    try {
      self.events.onMessageComplete();
    } catch (const std::exception&) {
      self.fail("event handler threw");
      return -1;
    }
    return HPE_OK;
  }

  FeedResult failed(llhttp_errno_t err) {
    state = State::kFailed;
    const char* reason = callback_error != nullptr ? callback_error : llhttp_get_error_reason(&parser);
    error = std::string(llhttp_errno_name(err)) + ": " + (reason != nullptr ? reason : "unknown");
    return {FeedStatus::kError, 0, error};
  }

  Http1Mode mode;
  Http1Events& events;
  Http1Limits limits;
  llhttp_settings_t settings{};
  llhttp_t parser{};
  State state = State::kParsing;
  std::string error;
  Http1Head head;
  std::size_t head_bytes = 0;
  const char* callback_error = nullptr;  ///< Static reason set by fail().
  bool field_done = false;  ///< The current header's value is complete, so the next name starts a new header.
  std::deque<bool> head_requests;  ///< One entry per noted request: whether it was HEAD.
};

Http1Parser::Http1Parser(Http1Mode mode, Http1Events& events, Http1Limits limits)
    : impl_(std::make_unique<Impl>(mode, events, limits)) {}

Http1Parser::~Http1Parser() = default;

FeedResult Http1Parser::feed(std::span<const std::uint8_t> bytes) {
  Impl& self = *impl_;
  if (self.state == State::kUpgraded) {
    return {FeedStatus::kUpgrade, 0, {}};
  }
  if (self.state == State::kFailed) {
    return {FeedStatus::kError, 0, self.error};
  }
  const char* data = reinterpret_cast<const char*>(bytes.data());
  const llhttp_errno_t err = llhttp_execute(&self.parser, data, bytes.size());
  if (err == HPE_OK) {
    return {FeedStatus::kOk, bytes.size(), {}};
  }
  if (err == HPE_PAUSED_UPGRADE) {
    self.state = State::kUpgraded;
    return {FeedStatus::kUpgrade, static_cast<std::size_t>(llhttp_get_error_pos(&self.parser) - data), {}};
  }
  FeedResult result = self.failed(err);
  const char* pos = llhttp_get_error_pos(&self.parser);
  result.consumed = pos == nullptr ? 0 : static_cast<std::size_t>(pos - data);
  return result;
}

FeedResult Http1Parser::finish() {
  Impl& self = *impl_;
  if (self.state == State::kUpgraded) {
    return {FeedStatus::kUpgrade, 0, {}};
  }
  if (self.state == State::kFailed) {
    return {FeedStatus::kError, 0, self.error};
  }
  const llhttp_errno_t err = llhttp_finish(&self.parser);
  return err == HPE_OK ? FeedResult{} : self.failed(err);
}

void Http1Parser::expectResponse(bool to_head_request) { impl_->head_requests.push_back(to_head_request); }

void Http1Parser::resumeAfterRejectedUpgrade() {
  if (impl_->state == State::kUpgraded && impl_->mode == Http1Mode::kRequest) {
    llhttp_resume_after_upgrade(&impl_->parser);
    impl_->state = State::kParsing;
  }
}

}  // namespace llmfw
