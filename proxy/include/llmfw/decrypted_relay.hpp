#pragma once
// Byte-exact relay between a client and the origin over two TLS connections.

#include <array>
#include <chrono>
#include <cstdint>
#include <memory>
#include <string>

#include <boost/asio/steady_timer.hpp>

#include "llmfw/common.hpp"
#include "llmfw/proxy_context.hpp"
#include "llmfw/relay_observer.hpp"
#include "llmfw/tls_stream.hpp"

namespace llmfw {

/// What the connection had established before the relay starts. All of it ends up in
/// the connection's capture.
struct DecryptedConnectionInfo {
  std::uint64_t connection_id = 0;
  std::string host;  ///< Normalized CONNECT host.
  std::uint16_t port = 0;
  std::string alpn;  ///< Negotiated with the client; empty means HTTP/1.1.
  std::string connect_user_agent;
  Clock::time_point started;  ///< When the CONNECT arrived.
  std::int64_t started_unix_us = 0;
  std::chrono::microseconds upstream_connect{0};
  std::chrono::microseconds client_handshake{0};
};

/// Copies decrypted bytes unchanged between the client's TLS stream (our leaf) and the
/// origin's (verified upstream), in both directions.
///
/// start():
///   - Registers with ctx.tunnels. If the proxy is already shutting down, it closes
///     both connections at once and records nothing. It deregisters when it ends.
///   - Counts connections_decrypted and logs one "decrypted open" line.
///   - Relays until one side ends. A clean TLS close (close_notify) from one side is
///     passed on as close_notify to the other; any other end (an error, a truncated
///     TLS stream, close(), or no bytes either way for listen.idle_timeout) closes both
///     connections at once. Closing is bounded: after kCloseGrace both are closed anyway.
///   - Hands every chunk to the observer, if there is one: client chunks once read,
///     origin chunks once forwarded (see RelayObserver). Calls its onClosed once
///     both connections are closed. The outcome passed is
///     kClientAborted or kUpstreamAborted for the side that ended first (close()
///     counts as the client's side), or kTimeout after listen.idle_timeout.
///   - Once both connections are closed, pushes one Capture{decrypted}, after
///     anything the observer pushed from onClosed. Its client is classified from
///     the observer's clientUserAgent.
/// Both streams must use the same strand as their executor, so the relay's state
/// needs no locking.
class DecryptedRelay final : public RegisteredConnection, public std::enable_shared_from_this<DecryptedRelay> {
 public:
  /// The longest the relay waits for a forwarded close_notify to be answered.
  static constexpr std::chrono::milliseconds kCloseGrace{1000};

  /// `observer` may be null.
  DecryptedRelay(std::unique_ptr<TlsStream> client, std::unique_ptr<TlsStream> upstream,
                 DecryptedConnectionInfo info, ProxyContext& ctx, std::unique_ptr<RelayObserver> observer = nullptr);

  /// Safe from any thread: the work runs on the streams' strand.
  void start();

  /// Ends the relay from any thread by closing both connections. The capture is still pushed.
  void close() override;

 private:
  using Buffer = std::array<std::uint8_t, 16 * 1024>;
  struct Direction {
    TlsStream& from;
    TlsStream& to;
    bool from_client;
    Buffer buffer{};
    Clock::time_point read_at{};  ///< When the bytes in buffer were read.
    std::uint64_t bytes = 0;
    bool busy = false;  ///< A read or write is in flight.
  };

  void pump(Direction& dir);
  void observe(Direction& dir, std::size_t n);
  /// `client_ended`: the client's connection is the one that ended (by a read from it or a write to it failing).
  void onEnded(Direction& dir, const boost::system::error_code& ec, bool client_ended);
  void beginClose(TlsStream* forward_close_to);
  void proceed();
  void armTimer(std::chrono::milliseconds after);
  void closeSockets();
  void finish();

  std::unique_ptr<TlsStream> client_;
  std::unique_ptr<TlsStream> upstream_;
  DecryptedConnectionInfo info_;
  ProxyContext& ctx_;
  asio::steady_timer timer_;
  std::unique_ptr<RelayObserver> observer_;
  Direction c2s_{*client_, *upstream_, true};
  Direction s2c_{*upstream_, *client_, false};
  ExchangeOutcomeTag end_ = ExchangeOutcomeTag::kClientAborted;  ///< Why the relay is ending.
  bool closing_ = false;
  TlsStream* shutdown_target_ = nullptr;  ///< Gets a close_notify passed on, if set.
  bool shutdown_started_ = false;
  bool shutdown_in_flight_ = false;
  bool sockets_closed_ = false;
  bool finished_ = false;
};

}  // namespace llmfw
