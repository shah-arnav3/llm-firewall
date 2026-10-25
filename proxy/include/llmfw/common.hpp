#pragma once
// Asio aliases and small enums shared across proxy components.

#include <chrono>
#include <cstdint>

#include <boost/asio/ip/tcp.hpp>

namespace llmfw {

namespace asio = boost::asio;
using tcp = asio::ip::tcp;
using Clock = std::chrono::steady_clock;

/// The wall-clock time, in Unix microseconds, at which steady time `at` happened.
inline std::int64_t unixMicros(Clock::time_point at) {
  const auto ago = std::chrono::duration_cast<std::chrono::system_clock::duration>(Clock::now() - at);
  return std::chrono::duration_cast<std::chrono::microseconds>((std::chrono::system_clock::now() - ago).time_since_epoch())
      .count();
}

/// Why a CONNECT was blind-tunneled. Mirrors proto llmfw.v1.TunnelReason.
enum class TunnelReasonTag {
  kNone,
  kUnscopedHost,
  kScopedNoCert,
  kUpstreamVerifyFailed,
  kClientTlsBreaker,
  kNonTlsPort,
  kClientSentEarly,
};

/// How an HTTP exchange ended. Mirrors proto llmfw.v1.ExchangeOutcome.
enum class ExchangeOutcomeTag {
  kComplete,
  kClientAborted,
  kUpstreamAborted,
  kTimeout,
  kParseError,
  kUpgraded,
};

}  // namespace llmfw
