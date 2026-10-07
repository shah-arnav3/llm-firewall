#include <gtest/gtest.h>

#include <memory>
#include <vector>

#include <boost/asio/io_context.hpp>

#include "llmfw/blind_tunnel.hpp"
#include "llmfw/proxy_context.hpp"

namespace llmfw {
namespace {

TEST(TunnelRegistry, CloseAllWithNothingOpenCallsBackAtOnce) {
  TunnelRegistry registry;
  bool called = false;
  registry.closeAll([&] { called = true; });
  EXPECT_TRUE(called);
}

TEST(TunnelRegistry, ExpiredTunnelsDoNotCountAsOpen) {
  TunnelRegistry registry;
  ASSERT_TRUE(registry.add(1, std::weak_ptr<BlindTunnel>()));
  EXPECT_EQ(registry.size(), 1u);
  bool called = false;
  registry.closeAll([&] { called = true; });
  EXPECT_TRUE(called);
  EXPECT_EQ(registry.size(), 0u);
}

TEST(TunnelRegistry, CallsBackOnlyWhenLastOpenTunnelIsRemoved) {
  asio::io_context io;  // Never run: close() only posts work to it.
  ProxyConfig config;
  HostScope scope({});
  ProxyCounters counters;
  CaptureQueue queue(10, 1 << 20, counters);
  ClientClassifier classifier({});
  CaptureBuildContext build{classifier, counters};
  TunnelRegistry registry;
  const std::string pac;
  ProxyContext ctx{config, scope, queue, counters, build, registry, pac};
  const auto tunnel = std::make_shared<BlindTunnel>(tcp::socket(io), 1, "host", 1, TunnelReasonTag::kUnscopedHost, "",
                                                    ctx, std::vector<std::uint8_t>{});
  ASSERT_TRUE(registry.add(1, tunnel));

  bool called = false;
  registry.closeAll([&] { called = true; });
  EXPECT_FALSE(called) << "a tunnel is still open";
  registry.remove(1);
  EXPECT_TRUE(called);
}

TEST(TunnelRegistry, RefusesNewTunnelsAfterCloseAll) {
  TunnelRegistry registry;
  registry.closeAll([] {});
  EXPECT_FALSE(registry.add(1, std::weak_ptr<BlindTunnel>()));
}

}  // namespace
}  // namespace llmfw
