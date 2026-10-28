package dev.llmfirewall.collector.coverage;

import dev.llmfirewall.proto.v1.ProxyStats;
import java.util.List;
import java.util.function.ToLongFunction;

/**
 * Turns the proxy's cumulative ProxyStats into coverage deltas. Each PROXY_* metric gets
 * the increase since the previous snapshot from the same proxy instance, under the
 * proxy_instance_id. Only the current instance is remembered: the first snapshot from
 * an instance counts in full, since a proxy starts its counters at zero. That includes
 * the first snapshot after a collector restart, which counts again what an earlier
 * collector process may already have recorded. A counter that goes down is treated as
 * having restarted from zero.
 *
 * <p>Not thread-safe: the receiver thread is its only caller.
 */
public final class ProxyStatsRecorder {

    private record Field(CoverageMetric metric, ToLongFunction<ProxyStats> value) {}

    private static final List<Field> FIELDS = List.of(
        new Field(CoverageMetric.PROXY_CAPTURES_DROPPED_QUEUE_FULL, ProxyStats::getCapturesDroppedQueueFull),
        new Field(CoverageMetric.PROXY_CAPTURES_DROPPED_IPC_UNAVAILABLE, ProxyStats::getCapturesDroppedIpcUnavailable),
        new Field(CoverageMetric.PROXY_REQUEST_BODIES_TRUNCATED, ProxyStats::getRequestBodiesTruncated),
        new Field(CoverageMetric.PROXY_RESPONSE_BODIES_TRUNCATED, ProxyStats::getResponseBodiesTruncated),
        new Field(CoverageMetric.PROXY_WS_MESSAGES_TRUNCATED, ProxyStats::getWsMessagesTruncated),
        new Field(CoverageMetric.PROXY_TUNNELS_UNSCOPED, ProxyStats::getTunnelsUnscoped),
        new Field(CoverageMetric.PROXY_TUNNELS_SCOPED_NO_CERT, ProxyStats::getTunnelsScopedNoCert),
        new Field(CoverageMetric.PROXY_TUNNELS_UPSTREAM_VERIFY_FAILED, ProxyStats::getTunnelsUpstreamVerifyFailed),
        new Field(CoverageMetric.PROXY_TUNNELS_CLIENT_TLS_BREAKER, ProxyStats::getTunnelsClientTlsBreaker),
        new Field(CoverageMetric.PROXY_CLIENT_TLS_HANDSHAKE_FAILURES, ProxyStats::getClientTlsHandshakeFailures),
        new Field(CoverageMetric.PROXY_HTTP_PARSE_ERRORS, ProxyStats::getHttpParseErrors),
        new Field(CoverageMetric.PROXY_WS_DECODE_ERRORS, ProxyStats::getWsDecodeErrors),
        new Field(CoverageMetric.PROXY_NON_CONNECT_REJECTED, ProxyStats::getNonConnectRequestsRejected));

    private final CoverageCounters coverage;
    private ProxyStats last;

    public ProxyStatsRecorder(CoverageCounters coverage) {
        this.coverage = coverage;
    }

    public void record(ProxyStats stats) {
        final boolean sameInstance = last != null && last.getProxyInstanceId().equals(stats.getProxyInstanceId());
        for (Field field : FIELDS) {
            final long now = field.value().applyAsLong(stats);
            final long before = sameInstance ? field.value().applyAsLong(last) : 0;
            final long delta = now >= before ? now - before : now;
            if (delta > 0) {
                coverage.add(field.metric(), stats.getProxyInstanceId(), delta);
            }
        }
        last = stats;
    }
}
