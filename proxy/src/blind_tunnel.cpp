#include "llmfw/blind_tunnel.hpp"

#include <boost/asio/connect.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/write.hpp>

#include "llmfw/log.hpp"

namespace llmfw {

namespace {

constexpr std::string_view kEstablished = "HTTP/1.1 200 Connection Established\r\n\r\n";
constexpr std::string_view kBadGateway =
    "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

std::int64_t nowUnixUs() {
  return std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::system_clock::now().time_since_epoch())
      .count();
}

const char* reasonName(TunnelReasonTag reason) {
  switch (reason) {
    case TunnelReasonTag::kUnscopedHost: return "unscoped_host";
    case TunnelReasonTag::kScopedNoCert: return "scoped_no_cert";
    case TunnelReasonTag::kUpstreamVerifyFailed: return "upstream_verify_failed";
    case TunnelReasonTag::kClientTlsBreaker: return "client_tls_breaker";
    case TunnelReasonTag::kNonTlsPort: return "non_tls_port";
    case TunnelReasonTag::kNone: break;
  }
  return "none";
}

}  // namespace

BlindTunnel::BlindTunnel(tcp::socket client, std::uint64_t connection_id, std::string host, std::uint16_t port,
                         TunnelReasonTag reason, std::string connect_user_agent, ProxyContext& ctx,
                         std::vector<std::uint8_t> client_leftover)
    : client_(std::move(client)),
      upstream_(client_.get_executor()),
      resolver_(client_.get_executor()),
      timer_(client_.get_executor()),
      connection_id_(connection_id),
      host_(std::move(host)),
      port_(port),
      reason_(reason),
      connect_user_agent_(std::move(connect_user_agent)),
      ctx_(ctx),
      client_leftover_(std::move(client_leftover)) {}

void BlindTunnel::start() {
  asio::dispatch(client_.get_executor(), [self = shared_from_this()] {
    self->started_ = Clock::now();
    self->started_unix_us_ = nowUnixUs();
    self->countAndLogOpen();
    self->armTimer(self->ctx_.config.upstream.connect_timeout);
    self->resolver_.async_resolve(self->host_, std::to_string(self->port_),
                                  [self](const boost::system::error_code& ec, const tcp::resolver::results_type& results) {
                                    self->onResolved(ec, results);
                                  });
  });
}

void BlindTunnel::close() {
  asio::post(client_.get_executor(), [self = shared_from_this()] { self->closeSockets(); });
}

void BlindTunnel::countAndLogOpen() {
  ProxyCounters& c = ctx_.counters;
  switch (reason_) {
    case TunnelReasonTag::kUnscopedHost: c.tunnels_unscoped.fetch_add(1, std::memory_order_relaxed); break;
    case TunnelReasonTag::kScopedNoCert: c.tunnels_scoped_no_cert.fetch_add(1, std::memory_order_relaxed); break;
    case TunnelReasonTag::kUpstreamVerifyFailed:
      c.tunnels_upstream_verify_failed.fetch_add(1, std::memory_order_relaxed);
      break;
    case TunnelReasonTag::kClientTlsBreaker:
      c.tunnels_client_tls_breaker.fetch_add(1, std::memory_order_relaxed);
      break;
    case TunnelReasonTag::kNonTlsPort:
    case TunnelReasonTag::kNone: break;
  }
  logInfo("tunnel open conn=" + std::to_string(connection_id_) + " host=" + host_ + ":" + std::to_string(port_) +
          " reason=" + reasonName(reason_));
}

void BlindTunnel::onResolved(const boost::system::error_code& ec, const tcp::resolver::results_type& results) {
  if (ec) {
    failUpstream("resolve: " + ec.message());
    return;
  }
  asio::async_connect(upstream_, results,
                      [self = shared_from_this()](const boost::system::error_code& connect_ec, const tcp::endpoint&) {
                        self->onConnected(connect_ec);
                      });
}

void BlindTunnel::onConnected(const boost::system::error_code& ec) {
  if (ec) {
    failUpstream("connect: " + ec.message());
    return;
  }
  connected_ = true;
  boost::system::error_code ignored;
  upstream_.set_option(tcp::no_delay(true), ignored);
  armTimer(ctx_.config.listen.idle_timeout);
  asio::async_write(client_, asio::buffer(kEstablished),
                    [self = shared_from_this()](const boost::system::error_code& write_ec, std::size_t) {
                      if (write_ec) {
                        self->closeSockets();
                        self->finish();
                        return;
                      }
                      self->sendLeftoverThenRelay();
                    });
}

void BlindTunnel::sendLeftoverThenRelay() {
  if (client_leftover_.empty()) {
    pump(c2s_);
    pump(s2c_);
    return;
  }
  asio::async_write(upstream_, asio::buffer(client_leftover_),
                    [self = shared_from_this()](const boost::system::error_code& ec, std::size_t written) {
                      if (ec) {
                        self->closeSockets();
                        self->finish();
                        return;
                      }
                      self->c2s_.bytes += written;
                      self->client_leftover_.clear();
                      self->pump(self->c2s_);
                      self->pump(self->s2c_);
                    });
}

void BlindTunnel::pump(Direction& dir) {
  dir.from.async_read_some(
      asio::buffer(dir.buffer), [self = shared_from_this(), &dir](const boost::system::error_code& ec, std::size_t n) {
        if (ec) {
          self->onDirectionDone(dir, ec);
          return;
        }
        self->armTimer(self->ctx_.config.listen.idle_timeout);
        asio::async_write(dir.to, asio::buffer(dir.buffer.data(), n),
                          [self, &dir](const boost::system::error_code& write_ec, std::size_t written) {
                            if (write_ec) {
                              self->onDirectionDone(dir, write_ec);
                              return;
                            }
                            dir.bytes += written;
                            self->pump(dir);
                          });
      });
}

void BlindTunnel::onDirectionDone(Direction& dir, const boost::system::error_code& ec) {
  dir.done = true;
  if (ec == asio::error::eof) {
    // A clean end of one direction: pass the half-close on and keep the other open.
    boost::system::error_code ignored;
    dir.to.shutdown(tcp::socket::shutdown_send, ignored);
  } else {
    closeSockets();
  }
  if (c2s_.done && s2c_.done) {
    finish();
  }
}

void BlindTunnel::armTimer(std::chrono::milliseconds after) {
  timer_.expires_after(after);
  timer_.async_wait([self = shared_from_this()](const boost::system::error_code& ec) {
    if (ec == asio::error::operation_aborted || self->finished_) {
      return;
    }
    if (self->connected_) {
      self->closeSockets();
    } else {
      // Cancels the pending resolve or connect, whose handler then replies 502.
      self->connect_timed_out_ = true;
      self->resolver_.cancel();
      boost::system::error_code ignored;
      self->upstream_.close(ignored);
    }
  });
}

void BlindTunnel::failUpstream(const std::string& what) {
  logWarn("tunnel upstream failed conn=" + std::to_string(connection_id_) + " host=" + host_ + ":" +
          std::to_string(port_) + " " + (connect_timed_out_ ? std::string("timed out") : what));
  finished_ = true;
  timer_.cancel();
  asio::async_write(client_, asio::buffer(kBadGateway),
                    [self = shared_from_this()](const boost::system::error_code&, std::size_t) {
                      boost::system::error_code ignored;
                      self->client_.close(ignored);
                    });
}

void BlindTunnel::closeSockets() {
  boost::system::error_code ignored;
  client_.close(ignored);
  upstream_.close(ignored);
  resolver_.cancel();
}

void BlindTunnel::finish() {
  if (finished_) {
    return;
  }
  finished_ = true;
  timer_.cancel();
  closeSockets();
  if (!connected_) {
    return;
  }
  TunnelObservation observation;
  observation.connection_id = connection_id_;
  observation.host = host_;
  observation.port = port_;
  observation.reason = reason_;
  observation.connect_user_agent = connect_user_agent_;
  observation.bytes_client_to_server = c2s_.bytes;
  observation.bytes_server_to_client = s2c_.bytes;
  observation.start_unix_us = started_unix_us_;
  observation.duration = std::chrono::duration_cast<std::chrono::microseconds>(Clock::now() - started_);
  (void)ctx_.queue.tryPush(buildTunnelCapture(ctx_.build, observation));
}

}  // namespace llmfw
