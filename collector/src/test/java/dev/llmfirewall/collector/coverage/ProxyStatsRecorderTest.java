package dev.llmfirewall.collector.coverage;

import static org.junit.jupiter.api.Assertions.assertEquals;

import dev.llmfirewall.collector.coverage.CoverageCounters.Delta;
import dev.llmfirewall.proto.v1.ProxyStats;
import java.time.Clock;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.List;
import org.junit.jupiter.api.Test;

class ProxyStatsRecorderTest {

    private static final Clock CLOCK = Clock.fixed(Instant.parse("2026-10-27T12:00:00Z"), ZoneOffset.UTC);
    private static final LocalDate DAY = LocalDate.of(2026, 10, 27);

    private final CoverageCounters coverage = new CoverageCounters(10, CLOCK);
    private final ProxyStatsRecorder recorder = new ProxyStatsRecorder(coverage);

    private static ProxyStats stats(String instance, long queueFull, long parseErrors) {
        return ProxyStats.newBuilder()
            .setProxyInstanceId(instance)
            .setCapturesDroppedQueueFull(queueFull)
            .setHttpParseErrors(parseErrors)
            .setConnectionsAccepted(1000)  // Not a coverage metric, so never recorded.
            .build();
    }

    @Test
    void theFirstSnapshotCountsInFull() {
        recorder.record(stats("a", 3, 1));
        assertEquals(List.of(new Delta(DAY, CoverageMetric.PROXY_CAPTURES_DROPPED_QUEUE_FULL, "a", 3),
                             new Delta(DAY, CoverageMetric.PROXY_HTTP_PARSE_ERRORS, "a", 1)),
                     coverage.drain());
    }

    @Test
    void laterSnapshotsCountOnlyTheIncrease() {
        recorder.record(stats("a", 3, 1));
        coverage.drain();
        recorder.record(stats("a", 5, 1));
        recorder.record(stats("a", 6, 1));
        assertEquals(List.of(new Delta(DAY, CoverageMetric.PROXY_CAPTURES_DROPPED_QUEUE_FULL, "a", 3)), coverage.drain());
    }

    @Test
    void aNewInstanceStartsFromZero() {
        recorder.record(stats("a", 7, 0));
        coverage.drain();
        recorder.record(stats("b", 2, 0));
        assertEquals(List.of(new Delta(DAY, CoverageMetric.PROXY_CAPTURES_DROPPED_QUEUE_FULL, "b", 2)), coverage.drain());
    }

    @Test
    void aCounterThatGoesDownHasRestartedFromZero() {
        recorder.record(stats("a", 7, 0));
        coverage.drain();
        recorder.record(stats("a", 2, 0));
        assertEquals(List.of(new Delta(DAY, CoverageMetric.PROXY_CAPTURES_DROPPED_QUEUE_FULL, "a", 2)), coverage.drain());
    }

    @Test
    void mapsEveryCoverageField() {
        recorder.record(ProxyStats.newBuilder()
            .setProxyInstanceId("a")
            .setCapturesDroppedQueueFull(1)
            .setCapturesDroppedIpcUnavailable(2)
            .setRequestBodiesTruncated(3)
            .setResponseBodiesTruncated(4)
            .setWsMessagesTruncated(5)
            .setTunnelsUnscoped(6)
            .setTunnelsScopedNoCert(7)
            .setTunnelsUpstreamVerifyFailed(8)
            .setTunnelsClientTlsBreaker(9)
            .setClientTlsHandshakeFailures(10)
            .setHttpParseErrors(11)
            .setWsDecodeErrors(12)
            .setNonConnectRequestsRejected(13)
            .build());
        final List<CoverageMetric> proxyMetrics = List.of(
            CoverageMetric.PROXY_CAPTURES_DROPPED_QUEUE_FULL, CoverageMetric.PROXY_CAPTURES_DROPPED_IPC_UNAVAILABLE,
            CoverageMetric.PROXY_REQUEST_BODIES_TRUNCATED, CoverageMetric.PROXY_RESPONSE_BODIES_TRUNCATED,
            CoverageMetric.PROXY_WS_MESSAGES_TRUNCATED, CoverageMetric.PROXY_TUNNELS_UNSCOPED,
            CoverageMetric.PROXY_TUNNELS_SCOPED_NO_CERT, CoverageMetric.PROXY_TUNNELS_UPSTREAM_VERIFY_FAILED,
            CoverageMetric.PROXY_TUNNELS_CLIENT_TLS_BREAKER, CoverageMetric.PROXY_CLIENT_TLS_HANDSHAKE_FAILURES,
            CoverageMetric.PROXY_HTTP_PARSE_ERRORS, CoverageMetric.PROXY_WS_DECODE_ERRORS,
            CoverageMetric.PROXY_NON_CONNECT_REJECTED);
        final List<Delta> deltas = coverage.drain();
        assertEquals(proxyMetrics.size(), deltas.size());
        for (int i = 0; i < proxyMetrics.size(); i++) {
            assertEquals(new Delta(DAY, proxyMetrics.get(i), "a", i + 1), deltas.get(i));
        }
    }
}
