#pragma once
// Loopback servers and blocking read helpers shared by the network tests.

#include <array>
#include <functional>
#include <string>
#include <thread>

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>

namespace llmfw::test {

namespace asio = boost::asio;
using tcp = asio::ip::tcp;

inline const std::string kEstablished = "HTTP/1.1 200 Connection Established\r\n\r\n";

/// A loopback upstream server that handles one connection on its own thread.
class Upstream {
 public:
  using Handler = std::function<void(tcp::socket&)>;

  explicit Upstream(Handler handler) : acceptor_(io_, {asio::ip::make_address("127.0.0.1"), 0}) {
    thread_ = std::thread([this, handler = std::move(handler)] {
      boost::system::error_code ec;
      tcp::socket socket = acceptor_.accept(ec);
      if (!ec) {
        handler(socket);
      }
    });
  }
  ~Upstream() {
    boost::system::error_code ignored;
    acceptor_.close(ignored);
    thread_.join();
  }
  Upstream(const Upstream&) = delete;
  Upstream& operator=(const Upstream&) = delete;

  [[nodiscard]] std::uint16_t port() const { return acceptor_.local_endpoint().port(); }

 private:
  asio::io_context io_;
  tcp::acceptor acceptor_;
  std::thread thread_;
};

/// Echoes until the peer stops sending, then closes.
inline void echo(tcp::socket& socket) {
  std::array<char, 4096> buf{};
  boost::system::error_code ec;
  while (true) {
    const std::size_t n = socket.read_some(asio::buffer(buf), ec);
    if (ec) {
      break;
    }
    asio::write(socket, asio::buffer(buf.data(), n), ec);
  }
  socket.close(ec);
}

/// A loopback port nothing is listening on.
inline std::uint16_t closedPort() {
  asio::io_context io;
  tcp::acceptor acceptor(io, {asio::ip::make_address("127.0.0.1"), 0});
  return acceptor.local_endpoint().port();
}

inline std::string readExactly(tcp::socket& socket, std::size_t n) {
  std::string out(n, '\0');
  asio::read(socket, asio::buffer(out));
  return out;
}

/// Reads until the peer closes, returning everything read.
inline std::string readToEnd(tcp::socket& socket) {
  std::string out;
  boost::system::error_code ec;
  asio::read(socket, asio::dynamic_buffer(out), ec);
  return out;
}

}  // namespace llmfw::test
