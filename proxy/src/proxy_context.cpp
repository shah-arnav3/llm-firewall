#include "llmfw/proxy_context.hpp"

#include <atomic>
#include <csignal>
#include <optional>
#include <thread>
#include <vector>

#include <boost/asio/io_context.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/asio/steady_timer.hpp>

#include "llmfw/blind_tunnel.hpp"
#include "llmfw/capture_sink.hpp"
#include "llmfw/cert_store.hpp"
#include "llmfw/client_classifier.hpp"
#include "llmfw/listener.hpp"
#include "llmfw/log.hpp"
#include "llmfw/metadata_logger.hpp"
#include "llmfw/pac.hpp"
#include "llmfw/random_id.hpp"
#include "llmfw/tls_breaker.hpp"
#include "llmfw/tls_client.hpp"
#include "llmfw/tls_server.hpp"
#include "llmfw/trust_verifier.hpp"

namespace llmfw {

namespace {

constexpr std::chrono::seconds kTunnelCloseGrace{2};
constexpr std::chrono::seconds kDrainGrace{2};
constexpr std::chrono::days kLeafExpiryWarning{30};

void logSummary(const ProxyCounters& c) {
  const auto v = [](const std::atomic<std::uint64_t>& a) { return std::to_string(a.load()); };
  logInfo("shutdown summary: connections_accepted=" + v(c.connections_accepted) +
          " connections_decrypted=" + v(c.connections_decrypted) + " tunnels_unscoped=" + v(c.tunnels_unscoped) +
          " tunnels_scoped_no_cert=" + v(c.tunnels_scoped_no_cert) +
          " tunnels_upstream_verify_failed=" + v(c.tunnels_upstream_verify_failed) +
          " tunnels_client_tls_breaker=" + v(c.tunnels_client_tls_breaker) +
          " client_tls_handshake_failures=" + v(c.client_tls_handshake_failures) +
          " http_parse_errors=" + v(c.http_parse_errors) + " ws_decode_errors=" + v(c.ws_decode_errors) +
          " non_connect_requests_rejected=" + v(c.non_connect_requests_rejected) +
          " captures_created=" + v(c.captures_created) +
          " captures_dropped_queue_full=" + v(c.captures_dropped_queue_full) +
          " captures_dropped_ipc_unavailable=" + v(c.captures_dropped_ipc_unavailable));
}

void warnIfLeafExpiresSoon(const LeafCertStore& certs) {
  const auto left = std::chrono::floor<std::chrono::days>(certs.notAfter() - std::chrono::system_clock::now());
  if (left < kLeafExpiryWarning) {
    logWarn("the leaf certificate expires in " + std::to_string(left.count()) +
            " days; run llmfw-setup certs --force to replace it");
  }
}

}  // namespace

bool TunnelRegistry::add(std::uint64_t connection_id, std::weak_ptr<RegisteredConnection> connection) {
  const std::lock_guard lock(mu_);
  if (closing_) {
    return false;
  }
  open_[connection_id] = std::move(connection);
  return true;
}

void TunnelRegistry::remove(std::uint64_t connection_id) {
  std::function<void()> on_empty;
  {
    const std::lock_guard lock(mu_);
    open_.erase(connection_id);
    if (closing_ && open_.empty()) {
      on_empty = std::exchange(on_empty_, nullptr);
    }
  }
  if (on_empty) {
    on_empty();
  }
}

void TunnelRegistry::closeAll(std::function<void()> on_empty) {
  std::vector<std::shared_ptr<RegisteredConnection>> to_close;
  bool nothing_open = false;
  {
    const std::lock_guard lock(mu_);
    closing_ = true;
    for (auto it = open_.begin(); it != open_.end();) {
      if (auto connection = it->second.lock()) {
        to_close.push_back(std::move(connection));
        ++it;
      } else {
        it = open_.erase(it);
      }
    }
    nothing_open = open_.empty();
    if (!nothing_open) {
      on_empty_ = std::move(on_empty);
    }
  }
  if (nothing_open && on_empty) {
    on_empty();
  }
  for (const auto& connection : to_close) {
    connection->close();
  }
}

std::size_t TunnelRegistry::size() const {
  const std::lock_guard lock(mu_);
  return open_.size();
}

struct ProxyApp::State {
  asio::io_context io;
  asio::signal_set signals{io, SIGINT, SIGTERM};
  asio::steady_timer grace_timer{io};
  Listener* listener = nullptr;
  TunnelRegistry* tunnels = nullptr;
  std::atomic<bool> shutting_down{false};  ///< A signal and requestStop() can both post beginShutdown.

  explicit State(unsigned threads) : io(static_cast<int>(threads)) {}

  /// Runs on an I/O thread.
  void beginShutdown() {
    if (shutting_down.exchange(true)) {
      return;
    }
    logInfo("shutting down: closing " + std::to_string(tunnels->size()) + " open tunnel(s)");
    boost::system::error_code ignored;
    signals.cancel(ignored);
    listener->stop();
    grace_timer.expires_after(kTunnelCloseGrace);
    grace_timer.async_wait([this](const boost::system::error_code& ec) {
      if (!ec) {
        logWarn("connections still open after the grace period; stopping anyway");
        io.stop();
      }
    });
    tunnels->closeAll([this] { asio::post(io, [this] { io.stop(); }); });
  }
};

ProxyApp::ProxyApp(ProxyConfig config) : config_(std::move(config)) {}

ProxyApp::~ProxyApp() = default;

void ProxyApp::requestStop() {
  const std::lock_guard lock(mu_);
  stop_requested_ = true;
  if (state_ != nullptr) {
    asio::post(state_->io, [s = state_] { s->beginShutdown(); });
  }
}

int ProxyApp::run() {
  if (config_.mode != CaptureMode::kMetadataOnly) {
    logError("proxy.mode: \"full\" is not implemented yet; use \"metadata_only\"");
    return kExitConfig;
  }

  std::optional<LeafCertStore> certs;
  std::shared_ptr<const UpstreamTrustVerifier> verifier;
  if (config_.decrypt) {
    try {
      certs.emplace(LeafCertStore::load(config_.certs));
    } catch (const CertStoreError& e) {
      logError(std::string("proxy.decrypt is on, but the certificates cannot be used: ") + e.what());
      return kExitCerts;
    }
    try {
      verifier = makeTrustVerifier(config_.upstream);
    } catch (const ConfigError& e) {
      logError(std::string("configuration: ") + e.what());
      return kExitConfig;
    }
    warnIfLeafExpiresSoon(*certs);
  }

  const std::string instance_id = randomUuid();  // Tells proxy starts apart in the logs.
  std::unique_ptr<MetadataLogger> sink;
  try {
    sink = std::make_unique<MetadataLogger>(config_.metadata_log, instance_id);
  } catch (const std::system_error& e) {
    logError(std::string("cannot open the metadata log: ") + e.what());
    return kExitSink;
  }

  ProxyCounters counters;
  CaptureQueue queue(config_.capture.queue_max_items, config_.capture.queue_max_bytes, counters);
  const ClientClassifier classifier(config_.clients);
  const CaptureBuildContext build{classifier, counters};
  const HostScope scope(config_.decrypt_hosts);
  TunnelRegistry tunnels;
  std::string pac;  // Rendered once the listener has bound, before any connection is accepted.
  ProxyContext ctx{config_, scope, queue, counters, build, tunnels, pac};
  CaptureDrain drain(queue, *sink, counters);
  drain.start();

  State state(config_.listen.io_threads);
  // Declared after `state`, so they are destroyed first: the connector joins its verify
  // threads while the io_context they post results to still exists.
  std::optional<ClientTlsBreaker> breaker;
  std::unique_ptr<ClientTlsTerminator> terminator;
  std::unique_ptr<UpstreamTlsConnector> connector;
  if (certs) {
    try {
      breaker.emplace(config_.listen.client_tls_breaker_cooldown);
      terminator = std::make_unique<ClientTlsTerminator>(*certs, config_.listen.client_alpn);
      connector = std::make_unique<UpstreamTlsConnector>(config_.upstream, verifier, config_.listen.client_alpn);
    } catch (const std::exception& e) {
      logError(std::string("cannot set up decryption: ") + e.what());
      drain.stop(kDrainGrace);
      return kExitCerts;
    }
    ctx.certs = &*certs;
    ctx.breaker = &*breaker;
    ctx.terminator = terminator.get();
    ctx.connector = connector.get();
  }
  std::unique_ptr<Listener> listener;
  try {
    listener = std::make_unique<Listener>(state.io, config_.listen, ctx);
  } catch (const std::exception& e) {
    logError("cannot listen on " + config_.listen.address + ":" + std::to_string(config_.listen.port) + ": " +
             e.what());
    drain.stop(kDrainGrace);
    return kExitBind;
  }
  pac = renderPac(pacTemplate(), listener->localEndpoint().port());
  state.listener = listener.get();
  state.tunnels = &tunnels;
  state.signals.async_wait([&state](const boost::system::error_code& ec, int) {
    if (!ec) {
      state.beginShutdown();
    }
  });
  listener->start();
  logInfo("llmfw-proxy listening on " + config_.listen.address + ":" +
          std::to_string(listener->localEndpoint().port()) + " instance=" + instance_id +
          " mode=metadata_only decrypt=" + (certs ? "on" : "off") + " log=" + config_.metadata_log.path.string());

  {
    const std::lock_guard lock(mu_);
    state_ = &state;
    if (stop_requested_) {
      asio::post(state.io, [&state] { state.beginShutdown(); });
    }
  }

  std::atomic<bool> failed{false};
  const auto serve = [&] {
    try {
      state.io.run();
    } catch (const std::exception& e) {
      logError(std::string("unexpected error on an I/O thread: ") + e.what());
      failed = true;
      state.io.stop();
    }
  };
  std::vector<std::thread> threads;
  for (unsigned i = 1; i < config_.listen.io_threads; ++i) {
    threads.emplace_back(serve);
  }
  serve();
  for (std::thread& t : threads) {
    t.join();
  }

  {
    const std::lock_guard lock(mu_);
    state_ = nullptr;
  }
  drain.stop(kDrainGrace);
  logSummary(counters);
  return failed ? kExitUnexpected : kExitOk;
}

}  // namespace llmfw
