#include "llmfw/decrypted_relay.hpp"

#include <boost/asio/dispatch.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/write.hpp>

#include "llmfw/capture_builder.hpp"
#include "llmfw/log.hpp"

namespace llmfw {

DecryptedRelay::DecryptedRelay(std::unique_ptr<TlsStream> client, std::unique_ptr<TlsStream> upstream,
                               DecryptedConnectionInfo info, ProxyContext& ctx, std::unique_ptr<RelayObserver> observer)
    : client_(std::move(client)),
      upstream_(std::move(upstream)),
      info_(std::move(info)),
      ctx_(ctx),
      timer_(client_->get_executor()),
      observer_(std::move(observer)) {}

void DecryptedRelay::start() {
  asio::dispatch(client_->get_executor(), [self = shared_from_this()] {
    if (!self->ctx_.tunnels.add(self->info_.connection_id, self)) {
      // The proxy is shutting down.
      self->finished_ = true;
      self->closeSockets();
      return;
    }
    self->ctx_.counters.connections_decrypted.fetch_add(1, std::memory_order_relaxed);
    logInfo("decrypted open conn=" + std::to_string(self->info_.connection_id) + " host=" + self->info_.host + ":" +
            std::to_string(self->info_.port) + " alpn=" + (self->info_.alpn.empty() ? "none" : self->info_.alpn));
    self->armTimer(self->ctx_.config.listen.idle_timeout);
    self->pump(self->c2s_);
    self->pump(self->s2c_);
  });
}

void DecryptedRelay::close() {
  asio::post(client_->get_executor(), [self = shared_from_this()] {
    if (self->finished_) {
      return;
    }
    self->closing_ = true;
    self->closeSockets();
    self->proceed();
  });
}

void DecryptedRelay::pump(Direction& dir) {
  if (closing_) {
    proceed();
    return;
  }
  dir.busy = true;
  dir.from.async_read_some(
      asio::buffer(dir.buffer), [self = shared_from_this(), &dir](const boost::system::error_code& ec, std::size_t n) {
        dir.busy = false;
        if (self->closing_) {
          // The other side has ended, so these bytes have nowhere to go.
          self->proceed();
          return;
        }
        if (ec) {
          self->onEnded(dir, ec, dir.from_client);
          return;
        }
        self->armTimer(self->ctx_.config.listen.idle_timeout);
        dir.read_at = Clock::now();
        dir.busy = true;
        asio::async_write(dir.to, asio::buffer(dir.buffer.data(), n),
                          [self, &dir](const boost::system::error_code& write_ec, std::size_t written) {
                            dir.busy = false;
                            dir.bytes += written;
                            if (!write_ec && self->observer_) {
                              self->observe(dir, written);
                            }
                            if (self->closing_) {
                              self->proceed();
                              return;
                            }
                            if (write_ec) {
                              self->onEnded(dir, write_ec, !dir.from_client);
                              return;
                            }
                            self->pump(dir);
                          });
      });
}

void DecryptedRelay::observe(Direction& dir, std::size_t n) {
  const std::span<const std::uint8_t> bytes(dir.buffer.data(), n);
  if (dir.from_client) {
    observer_->onClientBytes(bytes, dir.read_at);
  } else {
    observer_->onUpstreamBytes(bytes, dir.read_at);
  }
}

void DecryptedRelay::onEnded(Direction& dir, const boost::system::error_code& ec, bool client_ended) {
  if (!closing_) {
    end_ = client_ended ? ExchangeOutcomeTag::kClientAborted : ExchangeOutcomeTag::kUpstreamAborted;
  }
  // asio reports a received close_notify as eof; a TCP close without one is stream_truncated.
  beginClose(ec == asio::error::eof ? &dir.to : nullptr);
}

void DecryptedRelay::beginClose(TlsStream* forward_close_to) {
  if (closing_) {
    return;
  }
  closing_ = true;
  shutdown_target_ = forward_close_to;
  armTimer(kCloseGrace);
  if (forward_close_to == nullptr) {
    closeSockets();
  } else {
    // The other direction is reading from this stream. Cancel that read, so the
    // close_notify can be sent once nothing else is in flight on the stream.
    boost::system::error_code ignored;
    forward_close_to->next_layer().cancel(ignored);
  }
  proceed();
}

void DecryptedRelay::proceed() {
  if (finished_ || c2s_.busy || s2c_.busy || shutdown_in_flight_) {
    return;
  }
  if (shutdown_target_ != nullptr && !shutdown_started_ && !sockets_closed_) {
    shutdown_started_ = true;
    shutdown_in_flight_ = true;
    // Sends close_notify and waits for the peer's, or for an error once the grace timer closes the sockets.
    shutdown_target_->async_shutdown([self = shared_from_this()](const boost::system::error_code&) {
      self->shutdown_in_flight_ = false;
      self->proceed();
    });
    return;
  }
  finish();
}

void DecryptedRelay::armTimer(std::chrono::milliseconds after) {
  timer_.expires_after(after);
  timer_.async_wait([self = shared_from_this()](const boost::system::error_code& ec) {
    if (ec == asio::error::operation_aborted || self->finished_) {
      return;
    }
    // Idle while relaying, or the close grace period ran out.
    if (!self->closing_) {
      self->end_ = ExchangeOutcomeTag::kTimeout;
    }
    self->closing_ = true;
    self->closeSockets();
    self->proceed();
  });
}

void DecryptedRelay::closeSockets() {
  sockets_closed_ = true;
  boost::system::error_code ignored;
  client_->next_layer().close(ignored);
  upstream_->next_layer().close(ignored);
}

void DecryptedRelay::finish() {
  if (finished_) {
    return;
  }
  finished_ = true;
  timer_.cancel();
  closeSockets();
  std::string user_agent;
  if (observer_) {
    observer_->onClosed(end_);
    user_agent = observer_->clientUserAgent();
    observer_.reset();
  }
  DecryptedObservation observation;
  observation.connection_id = info_.connection_id;
  observation.host = info_.host;
  observation.port = info_.port;
  observation.alpn = info_.alpn;
  observation.connect_user_agent = info_.connect_user_agent;
  observation.user_agent = user_agent;
  observation.bytes_client_to_server = c2s_.bytes;
  observation.bytes_server_to_client = s2c_.bytes;
  observation.start_unix_us = info_.started_unix_us;
  observation.duration = std::chrono::duration_cast<std::chrono::microseconds>(Clock::now() - info_.started);
  observation.upstream_connect = info_.upstream_connect;
  observation.client_handshake = info_.client_handshake;
  (void)ctx_.queue.tryPush(buildDecryptedCapture(ctx_.build, observation));
  // Last, so shutdown never stops the I/O threads before this capture is queued.
  ctx_.tunnels.remove(info_.connection_id);
}

}  // namespace llmfw
