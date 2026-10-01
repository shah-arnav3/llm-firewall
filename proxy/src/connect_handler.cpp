#include "llmfw/connect_handler.hpp"

#include <algorithm>
#include <string_view>

namespace llmfw {

namespace {

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

}  // namespace llmfw
