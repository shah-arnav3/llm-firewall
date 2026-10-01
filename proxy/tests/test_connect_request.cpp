#include <gtest/gtest.h>

#include <random>
#include <string>
#include <vector>

#include "llmfw/connect_handler.hpp"

namespace llmfw {
namespace {

std::span<const std::uint8_t> bytes(const std::string& s) {
  return {reinterpret_cast<const std::uint8_t*>(s.data()), s.size()};
}

ProxyRequestParse parse(const std::string& head, ProxyRequest& out) { return parseProxyRequest(bytes(head), out); }

ProxyRequestParse parse(const std::string& head) {
  ProxyRequest out;
  return parse(head, out);
}

TEST(ParseProxyRequest, ParsesConnectAuthorityForm) {
  ProxyRequest req;
  ASSERT_EQ(parse("CONNECT claude.ai:443 HTTP/1.1\r\nHost: claude.ai:443\r\n\r\n", req), ProxyRequestParse::kComplete);
  EXPECT_EQ(req.kind, ProxyRequestKind::kConnect);
  EXPECT_EQ(req.host, "claude.ai");
  EXPECT_EQ(req.port, 443);
}

TEST(ParseProxyRequest, AcceptsHttp10AndNoHeaders) {
  ProxyRequest req;
  ASSERT_EQ(parse("CONNECT api.anthropic.com:8443 HTTP/1.0\r\n\r\n", req), ProxyRequestParse::kComplete);
  EXPECT_EQ(req.host, "api.anthropic.com");
  EXPECT_EQ(req.port, 8443);
  EXPECT_TRUE(req.user_agent.empty());
}

TEST(ParseProxyRequest, ParsesBracketedIpv6Authority) {
  ProxyRequest req;
  ASSERT_EQ(parse("CONNECT [2606:4700::1]:443 HTTP/1.1\r\n\r\n", req), ProxyRequestParse::kComplete);
  EXPECT_EQ(req.host, "2606:4700::1");
  EXPECT_EQ(req.port, 443);
  EXPECT_EQ(parse("CONNECT 2606:4700::1:443 HTTP/1.1\r\n\r\n"), ProxyRequestParse::kInvalid);
  EXPECT_EQ(parse("CONNECT [::1]443 HTTP/1.1\r\n\r\n"), ProxyRequestParse::kInvalid);
  EXPECT_EQ(parse("CONNECT []:443 HTTP/1.1\r\n\r\n"), ProxyRequestParse::kInvalid);
}

TEST(ParseProxyRequest, CapturesConnectUserAgent) {
  ProxyRequest req;
  ASSERT_EQ(parse("CONNECT claude.ai:443 HTTP/1.1\r\nuser-AGENT:   Claude/2.9 Electron/38  \r\n"
                  "User-Agent: second\r\n\r\n",
                  req),
            ProxyRequestParse::kComplete);
  EXPECT_EQ(req.user_agent, "Claude/2.9 Electron/38");
}

TEST(ParseProxyRequest, NeedMoreUntilBlankLine) {
  const std::string full = "CONNECT claude.ai:443 HTTP/1.1\r\nUser-Agent: x\r\n\r\n";
  for (std::size_t n = 0; n < full.size(); ++n) {
    EXPECT_EQ(parse(full.substr(0, n)), ProxyRequestParse::kNeedMore) << "prefix length " << n;
  }
  EXPECT_EQ(parse(full), ProxyRequestParse::kComplete);
}

TEST(ParseProxyRequest, ClassifiesAbsoluteFormGetAsOther) {
  ProxyRequest req;
  ASSERT_EQ(parse("GET http://claude.ai/ HTTP/1.1\r\nHost: claude.ai\r\n\r\n", req), ProxyRequestParse::kComplete);
  EXPECT_EQ(req.kind, ProxyRequestKind::kOther);
  EXPECT_TRUE(req.host.empty());
  EXPECT_EQ(parse("connect claude.ai:443 HTTP/1.1\r\n\r\n", req), ProxyRequestParse::kComplete);
  EXPECT_EQ(req.kind, ProxyRequestKind::kOther);
}

TEST(ParseProxyRequest, RejectsHeadOver16KiB) {
  const std::string start = "CONNECT claude.ai:443 HTTP/1.1\r\nX-Pad: ";
  const std::string end = "\r\n\r\n";
  const std::string at_limit = start + std::string(kMaxProxyRequestHeadBytes - start.size() - end.size(), 'a') + end;
  ASSERT_EQ(at_limit.size(), kMaxProxyRequestHeadBytes);
  EXPECT_EQ(parse(at_limit), ProxyRequestParse::kComplete);
  EXPECT_EQ(parse(start + std::string(kMaxProxyRequestHeadBytes, 'a') + end), ProxyRequestParse::kInvalid);
  // No blank line within the limit is invalid without waiting for more.
  EXPECT_EQ(parse(std::string(kMaxProxyRequestHeadBytes, 'a')), ProxyRequestParse::kInvalid);
}

TEST(ParseProxyRequest, RejectsMissingOrInvalidPort) {
  for (const char* target : {"claude.ai", "claude.ai:", "claude.ai:0", "claude.ai:65536", "claude.ai:44a3",
                             "claude.ai:+443", ":443", "claude.ai:0443443"}) {
    EXPECT_EQ(parse(std::string("CONNECT ") + target + " HTTP/1.1\r\n\r\n"), ProxyRequestParse::kInvalid) << target;
  }
  ProxyRequest req;
  ASSERT_EQ(parse("CONNECT claude.ai:65535 HTTP/1.1\r\n\r\n", req), ProxyRequestParse::kComplete);
  EXPECT_EQ(req.port, 65535);
}

TEST(ParseProxyRequest, RejectsMalformedRequestLinesAndHeaders) {
  for (const char* head : {
           "\r\n\r\n",
           "CONNECT claude.ai:443\r\n\r\n",
           "CONNECT claude.ai:443 HTTP/2\r\n\r\n",
           "CONNECT  claude.ai:443 HTTP/1.1\r\n\r\n",
           "CONNECT claude.ai:443 HTTP/1.1 extra\r\n\r\n",
           "CONNECT claude.ai:443 HTTP/1.1\r\nNoColonHere\r\n\r\n",
           "CONNECT claude.ai:443 HTTP/1.1\r\nUser-Agent: a\r\n folded\r\n\r\n",
           "CONNECT claude.ai:443 HTTP/1.1\r\nBad Name: x\r\n\r\n",
           "CONNECT claude.ai:443 HTTP/1.1\nUser-Agent: x\r\n\r\n",
           "CONNECT claude.ai:443 HTTP/1.1\r\nUser-Agent: a\rb\r\n\r\n",
       }) {
    EXPECT_EQ(parse(head), ProxyRequestParse::kInvalid) << head;
  }
}

TEST(ParseProxyRequest, ReportsHeadBytesForLeftoverHandling) {
  const std::string head = "CONNECT claude.ai:443 HTTP/1.1\r\nUser-Agent: x\r\n\r\n";
  const std::string with_tls_bytes = head + "\x16\x03\x01\x02\x00";
  ProxyRequest req;
  ASSERT_EQ(parse(with_tls_bytes, req), ProxyRequestParse::kComplete);
  EXPECT_EQ(req.head_bytes, head.size());
}

TEST(ParseProxyRequest, ResetsOutputOnEveryCall) {
  ProxyRequest req;
  ASSERT_EQ(parse("CONNECT claude.ai:443 HTTP/1.1\r\nUser-Agent: x\r\n\r\n", req), ProxyRequestParse::kComplete);
  EXPECT_EQ(parse("CONNECT", req), ProxyRequestParse::kNeedMore);
  EXPECT_TRUE(req.host.empty());
  EXPECT_TRUE(req.user_agent.empty());
  EXPECT_EQ(req.head_bytes, 0u);
}

// Seeded random inputs and mutations of a valid head. Run under the sanitizer build
// this catches out-of-bounds reads and crashes; libFuzzer is not available with Apple Clang.
TEST(ParseProxyRequest, SurvivesRandomAndMutatedInput) {
  const std::string valid = "CONNECT [::1]:443 HTTP/1.1\r\nUser-Agent: Claude/2.9\r\nHost: x\r\n\r\n";
  std::mt19937 rng(20261001);
  std::uniform_int_distribution<int> byte(0, 255);
  for (int i = 0; i < 20'000; ++i) {
    std::string input;
    if (i % 2 == 0) {
      input.resize(static_cast<std::size_t>(rng() % 256));
      for (char& c : input) {
        c = static_cast<char>(byte(rng));
      }
    } else {
      input = valid;
      for (int edits = 1 + static_cast<int>(rng() % 4); edits > 0; --edits) {
        const std::size_t at = rng() % input.size();
        switch (rng() % 3) {
          case 0: input[at] = static_cast<char>(byte(rng)); break;
          case 1: input.erase(at, 1); break;
          default: input.insert(at, 1, static_cast<char>(byte(rng))); break;
        }
        if (input.empty()) {
          input = "C";
        }
      }
    }
    ProxyRequest req;
    const ProxyRequestParse result = parse(input, req);
    if (result == ProxyRequestParse::kComplete) {
      ASSERT_LE(req.head_bytes, input.size());
      ASSERT_EQ(input.compare(req.head_bytes - 4, 4, "\r\n\r\n"), 0);
      if (req.kind == ProxyRequestKind::kConnect) {
        ASSERT_FALSE(req.host.empty());
        ASSERT_NE(req.port, 0);
      }
    }
  }
}

}  // namespace
}  // namespace llmfw
