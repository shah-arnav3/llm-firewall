#pragma once
// Asio aliases and small enums shared across proxy components.

#include <chrono>

#include <boost/asio/ip/tcp.hpp>

namespace llmfw {

namespace asio = boost::asio;
using tcp = asio::ip::tcp;
using Clock = std::chrono::steady_clock;

/// Why a CONNECT was blind-tunneled. Mirrors proto llmfw.v1.TunnelReason.
enum class TunnelReasonTag {
  kNone,
  kUnscopedHost,
  kScopedNoCert,
  kUpstreamVerifyFailed,
  kClientTlsBreaker,
  kNonTlsPort,
};

}  // namespace llmfw
