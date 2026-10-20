#include "llmfw/connect_handler.hpp"

#include <algorithm>
#include <string_view>

#include <boost/asio/dispatch.hpp>
#include <boost/asio/write.hpp>

#include "llmfw/blind_tunnel.hpp"
#include "llmfw/host_scope.hpp"
#include "llmfw/log.hpp"
#include "llmfw/pac.hpp"
#include "llmfw/tls_breaker.hpp"

namespace llmfw {

namespace {

constexpr std::string_view kBadRequest =
    "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
constexpr std::string_view kMethodNotAllowed =
    "HTTP/1.1 405 Method Not Allowed\r\nAllow: CONNECT\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
constexpr std::string_view kEstablished = "HTTP/1.1 200 Connection Established\r\n\r\n";
constexpr std::string_view kBadGateway =
    "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
constexpr std::size_t kReadChunkBytes = 4096;

std::int64_t nowUnixUs() {
  return std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::system_clock::now().time_since_epoch())
      .count();
}

std::string pacResponse(std::string_view pac) {
  return "HTTP/1.1 200 OK\r\nContent-Type: application/x-ns-proxy-autoconfig\r\nContent-Length: " +
         std::to_string(pac.size()) + "\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n" + std::string(pac);
}

constexpr std::string_view kCrlf = "\r\n";
constexpr std::string_view kHeadEnd = "\r\n\r\n";

/// RFC 9110 tchar: the characters allowed in a method or header name.
bool isTokenChar(char c) {
  if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
    return true;
  }
  return std::string_view("!#$%&'*+-.^_`|~").find(c) != std::string_view::npos;
}

bool isToken(std::string_view s) { return !s.empty() && std::all_of(s.begin(), s.end(), isTokenChar); }

bool equalsIgnoreCase(std::string_view a, std::string_view b) {
  return a.size() == b.size() && std::equal(a.begin(), a.end(), b.begin(), [](char x, char y) {
           const auto lower = [](char c) { return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c; };
           return lower(x) == lower(y);
         });
}

std::string_view trimOws(std::string_view s) {
  while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) {
    s.remove_prefix(1);
  }
  while (!s.empty() && (s.back() == ' ' || s.back() == '\t')) {
    s.remove_suffix(1);
  }
  return s;
}

bool parsePort(std::string_view digits, std::uint16_t& port) {
  if (digits.empty() || digits.size() > 5 || !std::all_of(digits.begin(), digits.end(), [](char c) {
        return c >= '0' && c <= '9';
      })) {
    return false;
  }
  unsigned value = 0;
  for (const char c : digits) {
    value = value * 10 + static_cast<unsigned>(c - '0');
  }
  if (value == 0 || value > 65535) {
    return false;
  }
  port = static_cast<std::uint16_t>(value);
  return true;
}

/// "host:port" or "[v6]:port". Host characters are checked later by HostScope::normalizeHost.
bool parseAuthority(std::string_view authority, std::string& host, std::uint16_t& port) {
  std::string_view host_part;
  std::string_view port_part;
  if (authority.starts_with('[')) {
    const std::size_t close = authority.find(']');
    if (close == std::string_view::npos || close + 1 >= authority.size() || authority[close + 1] != ':') {
      return false;
    }
    host_part = authority.substr(1, close - 1);
    port_part = authority.substr(close + 2);
  } else {
    const std::size_t colon = authority.rfind(':');
    if (colon == std::string_view::npos) {
      return false;
    }
    host_part = authority.substr(0, colon);
    port_part = authority.substr(colon + 1);
    if (host_part.find(':') != std::string_view::npos) {
      return false;  // An unbracketed IPv6 literal is ambiguous.
    }
  }
  if (host_part.empty() || !parsePort(port_part, port)) {
    return false;
  }
  host.assign(host_part);
  return true;
}

bool parseRequestLine(std::string_view line, ProxyRequest& out) {
  const std::size_t sp1 = line.find(' ');
  if (sp1 == std::string_view::npos) {
    return false;
  }
  const std::size_t sp2 = line.find(' ', sp1 + 1);
  if (sp2 == std::string_view::npos || line.find(' ', sp2 + 1) != std::string_view::npos) {
    return false;
  }
  const std::string_view method = line.substr(0, sp1);
  const std::string_view target = line.substr(sp1 + 1, sp2 - sp1 - 1);
  const std::string_view version = line.substr(sp2 + 1);
  if (!isToken(method) || target.empty() || (version != "HTTP/1.1" && version != "HTTP/1.0")) {
    return false;
  }
  out.method.assign(method);
  out.target.assign(target);
  if (method != "CONNECT") {
    out.kind = ProxyRequestKind::kOther;
    return true;
  }
  out.kind = ProxyRequestKind::kConnect;
  return parseAuthority(target, out.host, out.port);
}

bool parseHeaderLine(std::string_view line, ProxyRequest& out) {
  const std::size_t colon = line.find(':');
  if (colon == std::string_view::npos || !isToken(line.substr(0, colon))) {
    return false;  // Also rejects obsolete line folding: a leading space or tab is not a token char.
  }
  if (out.user_agent.empty() && equalsIgnoreCase(line.substr(0, colon), "user-agent")) {
    out.user_agent.assign(trimOws(line.substr(colon + 1)));
  }
  return true;
}

}  // namespace

ProxyRequestParse parseProxyRequest(std::span<const std::uint8_t> buffer, ProxyRequest& out) {
  out = ProxyRequest{};
  const std::string_view data(reinterpret_cast<const char*>(buffer.data()), buffer.size());

  const std::size_t end = data.find(kHeadEnd);
  if (end == std::string_view::npos) {
    return data.size() >= kMaxProxyRequestHeadBytes ? ProxyRequestParse::kInvalid : ProxyRequestParse::kNeedMore;
  }
  const std::size_t head_bytes = end + kHeadEnd.size();
  if (head_bytes > kMaxProxyRequestHeadBytes) {
    return ProxyRequestParse::kInvalid;
  }

  // Lines between the start and the CRLF that precedes the blank line.
  const std::string_view head = data.substr(0, end + kCrlf.size());
  std::size_t pos = 0;
  bool first = true;
  while (pos < head.size()) {
    const std::size_t eol = head.find(kCrlf, pos);
    const std::string_view line = head.substr(pos, eol - pos);
    if (line.find('\r') != std::string_view::npos || line.find('\n') != std::string_view::npos ||
        line.find('\0') != std::string_view::npos) {
      return ProxyRequestParse::kInvalid;
    }
    if (!(first ? parseRequestLine(line, out) : parseHeaderLine(line, out))) {
      return ProxyRequestParse::kInvalid;
    }
    first = false;
    pos = eol + kCrlf.size();
  }
  out.head_bytes = head_bytes;
  return ProxyRequestParse::kComplete;
}

ClientConnection::ClientConnection(tcp::socket socket, std::uint64_t connection_id, ProxyContext& ctx)
    : socket_(std::move(socket)), connection_id_(connection_id), ctx_(ctx), timer_(socket_.get_executor()) {}

void ClientConnection::start() {
  asio::dispatch(socket_.get_executor(), [self = shared_from_this()] {
    self->timer_.expires_after(self->ctx_.config.listen.idle_timeout);
    self->timer_.async_wait([self](const boost::system::error_code& ec) {
      if (!ec) {
        boost::system::error_code ignored;
        self->socket_.close(ignored);
      }
    });
    self->readMore();
  });
}

void ClientConnection::readMore() {
  head_buf_.resize(std::min(filled_ + kReadChunkBytes, kMaxProxyRequestHeadBytes));
  socket_.async_read_some(
      asio::buffer(head_buf_.data() + filled_, head_buf_.size() - filled_),
      [self = shared_from_this()](const boost::system::error_code& ec, std::size_t n) {
        if (ec) {
          self->timer_.cancel();  // The client closed, or the head timed out.
          return;
        }
        self->filled_ += n;
        ProxyRequest request;
        switch (parseProxyRequest({self->head_buf_.data(), self->filled_}, request)) {
          case ProxyRequestParse::kNeedMore: self->readMore(); return;
          case ProxyRequestParse::kInvalid:
            logWarn("rejected invalid proxy request conn=" + std::to_string(self->connection_id_));
            self->replyAndClose(std::string(kBadRequest));
            return;
          case ProxyRequestParse::kComplete: self->onHead(request); return;
        }
      });
}

void ClientConnection::onHead(const ProxyRequest& request) {
  if (request.kind != ProxyRequestKind::kConnect && request.method == "GET" && request.target == kPacPath) {
    logInfo("served PAC conn=" + std::to_string(connection_id_));
    replyAndClose(pacResponse(ctx_.pac));
    return;
  }
  if (request.kind != ProxyRequestKind::kConnect) {
    ctx_.counters.non_connect_requests_rejected.fetch_add(1, std::memory_order_relaxed);
    logInfo("rejected non-CONNECT request conn=" + std::to_string(connection_id_));
    replyAndClose(std::string(kMethodNotAllowed));
    return;
  }
  timer_.cancel();
  ScopeResult scope = decideScope(request.host, request.port, ctx_.scope, ctx_.certs, ctx_.breaker, Clock::now());
  std::vector<std::uint8_t> leftover(head_buf_.begin() + static_cast<std::ptrdiff_t>(request.head_bytes),
                                     head_buf_.begin() + static_cast<std::ptrdiff_t>(filled_));
  std::string host = scope.normalized_host.empty() ? request.host : scope.normalized_host;
  if (scope.reason == TunnelReasonTag::kNone && !leftover.empty()) {
    scope.reason = TunnelReasonTag::kClientSentEarly;
  }
  if (scope.reason == TunnelReasonTag::kNone) {
    decrypt(request, std::move(host));
    return;
  }
  std::make_shared<BlindTunnel>(std::move(socket_), connection_id_, std::move(host), request.port, scope.reason,
                                request.user_agent, ctx_, std::move(leftover))
      ->start();
}

void ClientConnection::decrypt(const ProxyRequest& request, std::string host) {
  info_.connection_id = connection_id_;
  info_.host = std::move(host);
  info_.port = request.port;
  info_.connect_user_agent = request.user_agent;
  info_.started = Clock::now();
  info_.started_unix_us = nowUnixUs();
  ctx_.connector->asyncConnect(
      socket_.get_executor(), info_.host, info_.port,
      [self = shared_from_this()](UpstreamResult result, std::unique_ptr<TlsStream> upstream) {
        self->onUpstream(std::move(result), std::move(upstream));
      },
      ctx_.upstream_override);
}

void ClientConnection::onUpstream(UpstreamResult result, std::unique_ptr<TlsStream> upstream) {
  const std::string where = "conn=" + std::to_string(connection_id_) + " host=" + info_.host;
  if (result.status == UpstreamResult::Status::kVerifyFailed) {
    logWarn("origin certificate rejected, tunneling instead " + where + " " + result.detail);
    std::make_shared<BlindTunnel>(std::move(socket_), connection_id_, info_.host, info_.port,
                                  TunnelReasonTag::kUpstreamVerifyFailed, info_.connect_user_agent, ctx_,
                                  std::vector<std::uint8_t>{})
        ->start();
    return;
  }
  if (result.status != UpstreamResult::Status::kOk) {
    logWarn("cannot reach the origin " + where + " " + result.detail);
    replyAndClose(std::string(kBadGateway));
    return;
  }
  upstream_ = std::move(upstream);
  info_.upstream_connect = result.connect_time;
  asio::async_write(socket_, asio::buffer(kEstablished),
                    [self = shared_from_this()](const boost::system::error_code& ec, std::size_t) {
                      if (ec) {
                        self->closeDecryptAttempt();
                        return;
                      }
                      self->client_tls_ =
                          std::make_unique<TlsStream>(std::move(self->socket_), self->ctx_.terminator->context());
                      self->ctx_.terminator->asyncHandshake(
                          *self->client_tls_, self->info_.host, self->ctx_.config.upstream.tls_handshake_timeout,
                          [self](const boost::system::error_code& handshake_ec, const ClientTlsResult& tls) {
                            self->onClientHandshake(handshake_ec, tls);
                          });
                    });
}

void ClientConnection::onClientHandshake(const boost::system::error_code& ec, const ClientTlsResult& result) {
  if (ec) {
    ctx_.counters.client_tls_handshake_failures.fetch_add(1, std::memory_order_relaxed);
    if (result.client_rejected_cert) {
      ctx_.breaker->recordFailure(info_.host, Clock::now());
      logWarn("client rejected our certificate, tunneling the host for a while conn=" +
              std::to_string(connection_id_) + " host=" + info_.host + " " + ec.message());
    } else {
      logWarn("client TLS handshake failed conn=" + std::to_string(connection_id_) + " host=" + info_.host + " " +
              ec.message());
    }
    closeDecryptAttempt();
    return;
  }
  info_.alpn = result.alpn;
  info_.client_handshake = std::chrono::duration_cast<std::chrono::microseconds>(result.handshake_time);
  std::make_shared<DecryptedRelay>(std::move(client_tls_), std::move(upstream_), std::move(info_), ctx_)->start();
}

void ClientConnection::closeDecryptAttempt() {
  boost::system::error_code ignored;
  socket_.close(ignored);
  if (client_tls_) {
    client_tls_->next_layer().close(ignored);
  }
  if (upstream_) {
    upstream_->next_layer().close(ignored);
  }
}

void ClientConnection::replyAndClose(std::string response) {
  timer_.cancel();
  response_ = std::move(response);
  asio::async_write(socket_, asio::buffer(response_),
                    [self = shared_from_this()](const boost::system::error_code&, std::size_t) {
                      boost::system::error_code ignored;
                      self->socket_.shutdown(tcp::socket::shutdown_both, ignored);
                      self->socket_.close(ignored);
                    });
}

}  // namespace llmfw
