#pragma once
// CONNECT pass-through without decryption.

#include <array>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include <boost/asio/steady_timer.hpp>

#include "llmfw/common.hpp"
#include "llmfw/proxy_context.hpp"

namespace llmfw {

/// Relays bytes between a client and host:port without inspecting them.
///
/// start():
///   1. Counts the tunnel by reason (tunnels_unscoped, tunnels_scoped_no_cert, ...;
///      kNonTlsPort has no counter) and logs one "tunnel open" line.
///   2. Resolves and connects within upstream.connect_timeout. On failure it replies
///      "502 Bad Gateway", logs the error and closes. No capture is made.
///   3. Replies "200 Connection Established", forwards `client_leftover` (bytes the
///      client sent after its CONNECT head), then copies bytes both ways.
///   4. When one side stops sending, the other side's sending half is shut down, and
///      the tunnel ends once both directions are done, either side errors, or no bytes
///      arrive in either direction for listen.idle_timeout.
///   5. On end, it pushes one Capture{tunnel} with the byte counts and duration.
/// Every handler runs on the client socket's executor, which must be a strand (or a
/// single-threaded context), so the tunnel's state needs no locking.
class BlindTunnel final : public std::enable_shared_from_this<BlindTunnel> {
 public:
  /// @param host normalized if normalization succeeded, otherwise as the client sent it.
  BlindTunnel(tcp::socket client, std::uint64_t connection_id, std::string host, std::uint16_t port,
              TunnelReasonTag reason, std::string connect_user_agent, ProxyContext& ctx,
              std::vector<std::uint8_t> client_leftover);

  /// Safe from any thread: the work runs on the client socket's executor.
  void start();

  /// Ends the tunnel from any thread, as if both sides had closed. The capture is
  /// still pushed if the tunnel was established.
  void close();

 private:
  using Buffer = std::array<std::uint8_t, 16 * 1024>;
  struct Direction {
    tcp::socket& from;
    tcp::socket& to;
    Buffer buffer{};
    std::uint64_t bytes = 0;
    bool done = false;
  };

  void countAndLogOpen();
  void onResolved(const boost::system::error_code& ec, const tcp::resolver::results_type& results);
  void onConnected(const boost::system::error_code& ec);
  void sendLeftoverThenRelay();
  void pump(Direction& dir);
  void onDirectionDone(Direction& dir, const boost::system::error_code& ec);
  void armTimer(std::chrono::milliseconds after);
  void failUpstream(const std::string& what);
  void closeSockets();
  void finish();

  tcp::socket client_;
  tcp::socket upstream_;
  tcp::resolver resolver_;
  asio::steady_timer timer_;
  std::uint64_t connection_id_;
  std::string host_;
  std::uint16_t port_;
  TunnelReasonTag reason_;
  std::string connect_user_agent_;
  ProxyContext& ctx_;
  std::vector<std::uint8_t> client_leftover_;
  Direction c2s_{client_, upstream_};
  Direction s2c_{upstream_, client_};
  bool connected_ = false;
  bool connect_timed_out_ = false;
  bool finished_ = false;
  Clock::time_point started_;
  std::int64_t started_unix_us_ = 0;
};

}  // namespace llmfw
