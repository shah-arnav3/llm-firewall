package dev.llmfirewall.collector;

import dev.llmfirewall.collector.config.CollectorConfig;
import dev.llmfirewall.collector.coverage.CaptureGapTracker;
import dev.llmfirewall.collector.coverage.CoverageCounters;
import dev.llmfirewall.collector.coverage.CoverageMetric;
import dev.llmfirewall.collector.coverage.ProxyStatsRecorder;
import dev.llmfirewall.collector.detect.Detection;
import dev.llmfirewall.collector.detect.DetectionEngine;
import dev.llmfirewall.collector.detect.SegmentDeduplicator;
import dev.llmfirewall.collector.detect.injection.HeuristicPhraseDetector;
import dev.llmfirewall.collector.detect.injection.HiddenContentDetector;
import dev.llmfirewall.collector.detect.pii.BuiltinPiiPatterns;
import dev.llmfirewall.collector.detect.pii.RegexPiiDetector;
import dev.llmfirewall.collector.ingest.CaptureReceiver;
import dev.llmfirewall.collector.ingest.FrameDecoder;
import dev.llmfirewall.collector.label.EndpointKey;
import dev.llmfirewall.collector.label.EndpointRouter;
import dev.llmfirewall.collector.label.LabeledExchange;
import dev.llmfirewall.collector.label.Labeler;
import dev.llmfirewall.collector.label.Segment;
import dev.llmfirewall.collector.label.adapters.AnthropicMessagesAdapter;
import dev.llmfirewall.collector.label.SchemaSurvey;
import dev.llmfirewall.collector.parse.ContentDecoder;
import dev.llmfirewall.collector.parse.JsonBodyParser;
import dev.llmfirewall.collector.parse.ParsedBody;
import dev.llmfirewall.collector.parse.ParserRegistry;
import dev.llmfirewall.collector.parse.SseReplyAssembler;
import dev.llmfirewall.collector.parse.SseStreamParser;
import dev.llmfirewall.proto.v1.Capture;
import dev.llmfirewall.proto.v1.Header;
import dev.llmfirewall.proto.v1.HttpRequest;
import dev.llmfirewall.proto.v1.HttpResponse;
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
 * captures by kind, parses each HTTP request and response body (which counts parse
 * failures and skipped media types), routes the request, surveys the bodies' JSON shape
 * on routed endpoints, labels their text (which counts unknown endpoints, schema drift,
 * adapter failures and segments by source), runs the built-in regex PII patterns, the
 * injection phrase heuristics and the hidden-content checks over the segments
 * (counting detections by category, subtype, source and endpoint name), records
 * coverage (capture-id gaps and the proxy's own stats), and logs both every
 * {@code summaryInterval} and at close. Parsed bodies, segments and detections are
 * dropped once counted. Log lines hold counts, metric names, media types, failure
 * codes, endpoint names, JSON key paths with value types, detector subtypes and
 * segment locations, and proxy instance ids only, never capture content.
 */
public final class Collector implements AutoCloseable {

    /** Distinct dimensions kept per coverage metric between summaries. */
    static final int MAX_DIMENSIONS_PER_METRIC = 1000;
    // Fixed until the collector section of the config is loaded: the example config's values.
    static final int MAX_DECODED_BODY_BYTES = 64 << 20;
    static final int JSON_MAX_NESTING_DEPTH = 200;
    static final int JSON_MAX_STRING_LENGTH = 32 << 20;
    static final int DEDUP_CACHE_ENTRIES = 100_000;
    static final int MIN_ENCODED_BLOB_CHARS = 512;

    private static final System.Logger LOG = System.getLogger(Collector.class.getName());

    private final CoverageCounters coverage;
    private final CaptureReceiver receiver;
    private final ParserRegistry parsers;
    private final EndpointRouter router = new EndpointRouter();
    private final SchemaSurvey survey;
    private final Labeler labeler;
    private final DetectionEngine detection;
    private final Duration summaryInterval;
    private final Map<Capture.PayloadCase, Long> captures = new EnumMap<>(Capture.PayloadCase.class);
    private ScheduledExecutorService scheduler;

    public Collector(CollectorConfig config, Clock clock, Duration summaryInterval) {
        this.coverage = new CoverageCounters(MAX_DIMENSIONS_PER_METRIC, clock);
        this.summaryInterval = summaryInterval;
        final ProxyStatsRecorder stats = new ProxyStatsRecorder(coverage);
        final JsonBodyParser json = new JsonBodyParser(JSON_MAX_NESTING_DEPTH, JSON_MAX_STRING_LENGTH);
        this.parsers = new ParserRegistry(new ContentDecoder(MAX_DECODED_BODY_BYTES), json, new SseStreamParser(), coverage);
        this.survey = new SchemaSurvey(json, coverage);
        this.labeler = new Labeler(new AnthropicMessagesAdapter(new SseReplyAssembler(json)), coverage);
        this.detection = new DetectionEngine(
            List.of(new RegexPiiDetector(BuiltinPiiPatterns.select(BuiltinPiiPatterns.allNames()))),
            List.of(new HeuristicPhraseDetector(), new HiddenContentDetector(MIN_ENCODED_BLOB_CHARS)), List.of(), new SegmentDeduplicator(DEDUP_CACHE_ENTRIES), coverage);
        this.receiver = new CaptureReceiver(config.ipc().socketDir(), config.ipc().socketName(),
                                            new FrameDecoder(config.ipc().maxFrameBytes()),
                                            new CaptureGapTracker(coverage), coverage, new CaptureReceiver.Sink() {
                                                @Override
                                                public void capture(Capture capture) {
                                                    countCapture(capture);
                                                    parseBodies(capture);
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

    private void parseBodies(Capture capture) {
        if (!capture.hasHttp()) {
            return;
        }
        final HttpRequest request = capture.getHttp().getRequest();
        final HttpResponse response = capture.getHttp().getResponse();
        final ParsedBody requestBody = parsers.parseBody(request.getBody(), header(request.getHeadersList(), "content-type"),
                                                         header(request.getHeadersList(), "content-encoding"), "req");
        final ParsedBody responseBody = parsers.parseBody(response.getBody(),
                                                          header(response.getHeadersList(), "content-type"),
                                                          header(response.getHeadersList(), "content-encoding"), "resp");
        final String host = request.getHost().isEmpty() ? capture.getHttp().getConnectHost() : request.getHost();
        final EndpointKey endpoint = router.route(host, request.getMethod(), request.getTarget());
        survey.survey(endpoint, requestBody);
        survey.survey(endpoint, responseBody);
        final LabeledExchange labeled = labeler.label(endpoint, requestBody, responseBody);
        for (Segment segment : labeled.result().segments()) {
            coverage.increment(CoverageMetric.SEGMENTS_LABELED, segment.source() + " " + segment.direction());
        }
        final String endpointName = endpoint.known() ? endpoint.name() : "unknown";
        for (Detection d : detection.detect(labeled)) {
            coverage.increment(CoverageMetric.DETECTIONS,
                               d.category() + " " + d.subtype() + " " + d.segment().source() + " " + endpointName);
        }
    }

    /** The first value of a header, matched ignoring case; null if absent or redacted. */
    private static String header(List<Header> headers, String name) {
        for (Header h : headers) {
            if (h.getName().equalsIgnoreCase(name) && !h.getRedacted()) {
                return h.getValue();
            }
        }
        return null;
    }

    private synchronized void countCapture(Capture capture) {
        captures.merge(capture.getPayloadCase(), 1L, Long::sum);
    }
}
