package dev.llmfirewall.collector.detect;

import static org.junit.jupiter.api.Assertions.assertEquals;

import dev.llmfirewall.collector.coverage.CoverageCounters;
import dev.llmfirewall.collector.label.Direction;
import dev.llmfirewall.collector.label.EndpointKey;
import dev.llmfirewall.collector.label.LabelResult;
import dev.llmfirewall.collector.label.LabeledExchange;
import dev.llmfirewall.collector.label.Segment;
import dev.llmfirewall.collector.label.Source;
import java.time.Clock;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import org.junit.jupiter.api.Test;

class DetectionEngineTest {

    private static final EndpointKey ENDPOINT =
        new EndpointKey("messages_api", "api.anthropic.com", "POST", "/v1/messages", Map.of(), true);

    private final CoverageCounters coverage = new CoverageCounters(10, Clock.systemDefaultZone());

    /** Records the location of every segment it is given and returns {@code hits} for it. */
    private static final class Fake implements Detector {
        final String name;
        final FindingCategory category;
        final Function<Segment, List<Detection>> hits;
        final List<String> seen = new ArrayList<>();

        Fake(String name, FindingCategory category, Function<Segment, List<Detection>> hits) {
            this.name = name;
            this.category = category;
            this.hits = hits;
        }

        Fake(String name, FindingCategory category) {
            this(name, category, s -> List.of());
        }

        @Override public String name() { return name; }
        @Override public int version() { return 1; }
        @Override public FindingCategory category() { return category; }

        @Override
        public List<Detection> detect(Segment segment) {
            seen.add(segment.location());
            return hits.apply(segment);
        }
    }

    private static Detection hit(Segment segment, String detector, String subtype, int start, int end, double score) {
        return new Detection(detector, 1, FindingCategory.PII, subtype, segment, start, end, score);
    }

    private static Segment segment(Source source, Direction direction) {
        return new Segment(source, direction, "some text here", source + " " + direction);
    }

    private static LabeledExchange exchange(Segment... segments) {
        return new LabeledExchange(ENDPOINT, "test@1",
                                   new LabelResult(List.of(segments), Set.of(), new LabelResult.Attributes(Optional.empty(), false)));
    }

    /** The categories whose detector saw a segment of this source and direction. */
    private static List<String> routedTo(Source source, Direction direction) {
        final Fake pii = new Fake("pii", FindingCategory.PII);
        final Fake injection = new Fake("injection", FindingCategory.INJECTION);
        final Fake exfil = new Fake("exfil", FindingCategory.EXFIL);
        new DetectionEngine(List.of(pii), List.of(injection), List.of(exfil),
                            new CoverageCounters(10, Clock.systemDefaultZone()))
            .detect(exchange(segment(source, direction)));
        final List<String> out = new ArrayList<>();
        for (Fake f : List.of(pii, injection, exfil)) {
            if (!f.seen.isEmpty()) {
                out.add(f.name);
            }
        }
        return out;
    }

    private Map<String, Long> counted() {
        final Map<String, Long> out = new HashMap<>();
        coverage.drain().forEach(d -> out.merge(d.metric() + "[" + d.dimension() + "]", d.delta(), Long::sum));
        return out;
    }

    @Test
    void userTypedGetsPiiButNeverInjection() {
        assertEquals(List.of("pii"), routedTo(Source.USER_TYPED, Direction.OUTBOUND));
    }

    @Test
    void attachmentAndToolResultGetPiiAndInjection() {
        assertEquals(List.of("pii", "injection"), routedTo(Source.ATTACHMENT, Direction.OUTBOUND));
        assertEquals(List.of("pii", "injection"), routedTo(Source.TOOL_RESULT, Direction.OUTBOUND));
    }

    @Test
    void serverToolResultGetsInjectionOnly() {
        assertEquals(List.of("injection"), routedTo(Source.SERVER_TOOL_RESULT, Direction.INBOUND));
    }

    @Test
    void modelOutputGetsExfilOnlyAndOnlyInbound() {
        assertEquals(List.of("exfil"), routedTo(Source.MODEL_OUTPUT, Direction.INBOUND));
        assertEquals(List.of(), routedTo(Source.MODEL_OUTPUT, Direction.OUTBOUND));
    }

    @Test
    void unknownOutboundGetsPiiAndInjection() {
        assertEquals(List.of("pii", "injection"), routedTo(Source.UNKNOWN, Direction.OUTBOUND));
    }

    @Test
    void unknownInboundGetsInjectionOnly() {
        assertEquals(List.of("injection"), routedTo(Source.UNKNOWN, Direction.INBOUND));
    }

    @Test
    void failingDetectorDoesNotAffectOthers() {
        final Fake broken = new Fake("broken", FindingCategory.PII, x -> {
            throw new IllegalStateException("boom");
        });
        final Fake working = new Fake("working", FindingCategory.PII, x -> List.of(hit(x, "working", "email", 0, 4, 1.0)));
        final Segment s = segment(Source.USER_TYPED, Direction.OUTBOUND);
        final List<Detection> found = new DetectionEngine(List.of(broken, working), List.of(), List.of(), coverage)
            .detect(exchange(s, s));
        assertEquals(List.of(hit(s, "working", "email", 0, 4, 1.0), hit(s, "working", "email", 0, 4, 1.0)), found);
        assertEquals(Map.of("DETECTOR_FAILURE[broken]", 2L), counted());
    }

    @Test
    void overlappingDetectionsAreMergedKeepingMaxScore() {
        final Segment s = segment(Source.UNKNOWN, Direction.OUTBOUND);
        final Fake model = new Fake("model", FindingCategory.PII, x -> List.of(
            hit(x, "model", "PERSON", 5, 9, 0.7),
            hit(x, "model", "PERSON", 0, 6, 0.9),   // Overlaps 5-9: merged into 0-9 at 0.9.
            hit(x, "model", "PERSON", 9, 12, 0.5),  // Touches 0-9 but does not overlap: kept.
            hit(x, "model", "EMAIL", 2, 4, 1.0)));  // Another subtype: kept.
        final Fake other = new Fake("other", FindingCategory.PII, x -> List.of(hit(x, "other", "PERSON", 1, 3, 0.4)));
        final List<Detection> found = new DetectionEngine(List.of(model, other), List.of(), List.of(), coverage)
            .detect(exchange(s));
        // Another detector's overlapping PERSON is kept too.
        assertEquals(List.of(hit(s, "model", "PERSON", 0, 9, 0.9),
                             hit(s, "other", "PERSON", 1, 3, 0.4),
                             hit(s, "model", "EMAIL", 2, 4, 1.0),
                             hit(s, "model", "PERSON", 9, 12, 0.5)),
                     found);
    }

    @Test
    void returnsDetectionsInSegmentOrder() {
        final Segment first = new Segment(Source.USER_TYPED, Direction.OUTBOUND, "aaaa", "req:$.a");
        final Segment second = new Segment(Source.USER_TYPED, Direction.OUTBOUND, "bbbb", "req:$.b");
        // The first segment's hit starts later, but segment order wins.
        final Fake pii = new Fake("pii", FindingCategory.PII,
                                  x -> List.of(hit(x, "pii", "t", x == first ? 3 : 0, 4, 1.0)));
        final List<Detection> found = new DetectionEngine(List.of(pii), List.of(), List.of(), coverage)
            .detect(exchange(first, second));
        assertEquals(List.of("req:$.a", "req:$.b"), found.stream().map(d -> d.segment().location()).toList());
    }
}
