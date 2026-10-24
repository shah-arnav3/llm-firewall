#pragma once
// What a decrypted relay reports about the bytes it forwards.

#include <cstdint>
#include <span>
#include <string>

#include "llmfw/common.hpp"

namespace llmfw {

/// Sees the decrypted bytes of one connection after the relay has forwarded them, so
/// nothing it does can delay or change the traffic. Calls come from the relay's
/// strand, one at a time, in the order the bytes were read in each direction.
class RelayObserver {
 public:
  virtual ~RelayObserver() = default;
  /// Bytes from the client, already written to the origin. `at` is when they were read.
  virtual void onClientBytes(std::span<const std::uint8_t> bytes, Clock::time_point at) = 0;
  /// Bytes from the origin, already written to the client. `at` is when they were read.
  virtual void onUpstreamBytes(std::span<const std::uint8_t> bytes, Clock::time_point at) = 0;
  /// The relay has ended; no more calls follow. `unfinished` is the outcome for an
  /// exchange still in progress: which side ended the connection, or a timeout.
  virtual void onClosed(ExchangeOutcomeTag unfinished) = 0;
  /// The User-Agent the client sent inside TLS, or empty if none was seen.
  [[nodiscard]] virtual std::string clientUserAgent() const { return {}; }
};

}  // namespace llmfw
