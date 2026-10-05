#pragma once
// Loopback TCP acceptor.

#include <atomic>
#include <cstdint>

#include <boost/asio/io_context.hpp>
#include <boost/asio/steady_timer.hpp>

#include "llmfw/common.hpp"
#include "llmfw/config.hpp"
#include "llmfw/proxy_context.hpp"

namespace llmfw {

/// Accepts client connections on listen.address:listen.port.
/// Every accepted socket gets its own strand, TCP_NODELAY and the next connection id
/// (starting at 1), is counted in connections_accepted and is handed to a new
/// ClientConnection. An accept error is logged and accepting resumes after 100 ms.
/// Pending handlers refer to the Listener, so it must outlive the io_context's run.
class Listener {
 public:
  /// Binds and listens with SO_REUSEADDR. Port 0 picks a free port (see localEndpoint()).
  /// @throws ConfigError if the address is not a loopback literal.
  /// @throws boost::system::system_error if the bind or listen fails.
  Listener(asio::io_context& io, const ListenConfig& cfg, ProxyContext& ctx);

  /// Starts accepting. Call once.
  void start();
  /// Stops accepting; open connections are unaffected. Safe from any thread.
  void stop();

  [[nodiscard]] tcp::endpoint localEndpoint() const;

 private:
  void doAccept();

  asio::io_context& io_;
  ProxyContext& ctx_;
  tcp::acceptor acceptor_;  ///< Runs on its own strand, so stop() cannot race an accept.
  asio::steady_timer retry_timer_;
  std::uint64_t next_connection_id_ = 1;
};

}  // namespace llmfw
