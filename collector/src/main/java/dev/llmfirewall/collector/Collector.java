package dev.llmfirewall.collector;

import dev.llmfirewall.collector.config.CollectorConfig;
import dev.llmfirewall.collector.coverage.CaptureGapTracker;
import dev.llmfirewall.collector.coverage.CoverageCounters;
import dev.llmfirewall.collector.coverage.ProxyStatsRecorder;
import dev.llmfirewall.collector.ingest.CaptureReceiver;
import dev.llmfirewall.collector.ingest.FrameDecoder;
import dev.llmfirewall.proto.v1.Capture;
import dev.llmfirewall.proto.v1.ProxyStats;
import java.io.IOException;
import java.time.Clock;
import java.time.Duration;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

/**
 * The running collector, as far as it is built: it receives the proxy's frames, counts
 * captures by kind, records coverage (capture-id gaps and the proxy's own stats), and
 * logs both every {@code summaryInterval} and at close. Log lines hold counts, metric
 * names and proxy instance ids only, never capture content.
 */
public final class Collector implements AutoCloseable {

    /** Distinct dimensions kept per coverage metric between summaries. */
    static final int MAX_DIMENSIONS_PER_METRIC = 1000;

    private static final System.Logger LOG = System.getLogger(Collector.class.getName());

    private final CoverageCounters coverage;
    private final CaptureReceiver receiver;
    private final Duration summaryInterval;
    private final Map<Capture.PayloadCase, Long> captures = new EnumMap<>(Capture.PayloadCase.class);
    private ScheduledExecutorService scheduler;

    public Collector(CollectorConfig config, Clock clock, Duration summaryInterval) {
        this.coverage = new CoverageCounters(MAX_DIMENSIONS_PER_METRIC, clock);
        this.summaryInterval = summaryInterval;
        final ProxyStatsRecorder stats = new ProxyStatsRecorder(coverage);
        this.receiver = new CaptureReceiver(config.ipc().socketDir(), config.ipc().socketName(),
                                            new FrameDecoder(config.ipc().maxFrameBytes()),
                                            new CaptureGapTracker(coverage), coverage, new CaptureReceiver.Sink() {
                                                @Override
                                                public void capture(Capture capture) {
                                                    countCapture(capture);
                                                }

                                                @Override
                                                public void stats(ProxyStats proxyStats) {
                                                    stats.record(proxyStats);
                                                }
                                            });
    }

    /** Binds the socket and starts receiving. @throws IOException as {@link CaptureReceiver#start()} does */
    public void start() throws IOException {
        receiver.start();
        scheduler = Executors.newSingleThreadScheduledExecutor(r -> Thread.ofPlatform().daemon().name("summary").unstarted(r));
        scheduler.scheduleAtFixedRate(this::logSummary, summaryInterval.toMillis(), summaryInterval.toMillis(),
                                      TimeUnit.MILLISECONDS);
    }

    /** Captures received so far, by payload kind. */
    public synchronized Map<Capture.PayloadCase, Long> captureCounts() {
        return Map.copyOf(captures);
    }

    /** Logs and resets the coverage counted since the last summary, with the capture totals. */
    public List<CoverageCounters.Delta> logSummary() {
        final List<CoverageCounters.Delta> deltas = coverage.drain();
        final String counts = captureCounts().entrySet().stream()
            .map(e -> e.getKey().name().toLowerCase() + "=" + e.getValue())
            .sorted()
            .collect(Collectors.joining(" "));
        final String coverageText = deltas.stream()
            .map(d -> d.metric() + (d.dimension().isEmpty() ? "" : "[" + d.dimension() + "]") + "+" + d.delta())
            .collect(Collectors.joining(" "));
        LOG.log(System.Logger.Level.INFO, "captures received: {0}; coverage since last summary: {1}",
                counts.isEmpty() ? "none" : counts, coverageText.isEmpty() ? "none" : coverageText);
        return deltas;
    }

    /** Stops receiving, then logs a last summary. */
    @Override
    public void close() throws IOException {
        if (scheduler != null) {
            scheduler.shutdownNow();
        }
        receiver.close();
        logSummary();
    }

    private synchronized void countCapture(Capture capture) {
        captures.merge(capture.getPayloadCase(), 1L, Long::sum);
    }
}
