#include "llmfw/listener.hpp"

#include <boost/asio/post.hpp>
#include <boost/asio/strand.hpp>

#include "llmfw/connect_handler.hpp"
#include "llmfw/log.hpp"

namespace llmfw {

namespace {

constexpr std::chrono::milliseconds kAcceptRetryDelay{100};

tcp::endpoint loopbackEndpoint(const ListenConfig& cfg) {
  boost::system::error_code ec;
  const asio::ip::address address = asio::ip::make_address(cfg.address, ec);
  if (ec || !address.is_loopback()) {
    throw ConfigError("proxy.listen_address: must be a loopback address, got \"" + cfg.address + "\"");
  }
  return {address, cfg.port};
}

}  // namespace

Listener::Listener(asio::io_context& io, const ListenConfig& cfg, ProxyContext& ctx)
    : io_(io), ctx_(ctx), acceptor_(asio::make_strand(io)), retry_timer_(acceptor_.get_executor()) {
  const tcp::endpoint endpoint = loopbackEndpoint(cfg);
  acceptor_.open(endpoint.protocol());
  acceptor_.set_option(tcp::acceptor::reuse_address(true));
  acceptor_.bind(endpoint);
  acceptor_.listen();
}

void Listener::start() {
  asio::post(acceptor_.get_executor(), [this] { doAccept(); });
}

void Listener::stop() {
  asio::post(acceptor_.get_executor(), [this] {
    boost::system::error_code ignored;
    acceptor_.close(ignored);
    retry_timer_.cancel();
  });
}

tcp::endpoint Listener::localEndpoint() const { return acceptor_.local_endpoint(); }

void Listener::doAccept() {
  acceptor_.async_accept(asio::make_strand(io_), [this](const boost::system::error_code& ec, tcp::socket socket) {
    if (!acceptor_.is_open()) {
      return;
    }
    if (ec) {
      logWarn("accept failed: " + ec.message());
      retry_timer_.expires_after(kAcceptRetryDelay);
      retry_timer_.async_wait([this](const boost::system::error_code& wait_ec) {
        if (!wait_ec && acceptor_.is_open()) {
          doAccept();
        }
      });
      return;
    }
    ctx_.counters.connections_accepted.fetch_add(1, std::memory_order_relaxed);
    boost::system::error_code ignored;
    socket.set_option(tcp::no_delay(true), ignored);
    std::make_shared<ClientConnection>(std::move(socket), next_connection_id_++, ctx_)->start();
    doAccept();
  });
}

}  // namespace llmfw
