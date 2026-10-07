#include "llmfw/connect_handler.hpp"

#include <algorithm>
#include <string_view>

#include <boost/asio/dispatch.hpp>
#include <boost/asio/write.hpp>

#include "llmfw/blind_tunnel.hpp"
#include "llmfw/host_scope.hpp"
#include "llmfw/log.hpp"
#include "llmfw/pac.hpp"

namespace llmfw {

namespace {

constexpr std::string_view kBadRequest =
    "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
constexpr std::string_view kMethodNotAllowed =
    "HTTP/1.1 405 Method Not Allowed\r\nAllow: CONNECT\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
constexpr std::size_t kReadChunkBytes = 4096;

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
  const ScopeResult scope = decideScope(request.host, request.port, ctx_.scope);
  std::vector<std::uint8_t> leftover(head_buf_.begin() + static_cast<std::ptrdiff_t>(request.head_bytes),
                                     head_buf_.begin() + static_cast<std::ptrdiff_t>(filled_));
  std::string host = scope.normalized_host.empty() ? request.host : scope.normalized_host;
  std::make_shared<BlindTunnel>(std::move(socket_), connection_id_, std::move(host), request.port, scope.reason,
                                request.user_agent, ctx_, std::move(leftover))
      ->start();
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
