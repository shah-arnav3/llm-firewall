package dev.llmfirewall.collector.coverage;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.time.Clock;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.List;
import org.junit.jupiter.api.Test;

class CaptureGapTrackerTest {

    private static final Clock CLOCK = Clock.fixed(Instant.parse("2026-10-27T12:00:00Z"), ZoneOffset.UTC);
    private static final LocalDate DAY = LocalDate.of(2026, 10, 27);

    private final CoverageCounters coverage = new CoverageCounters(10, CLOCK);
    private final CaptureGapTracker tracker = new CaptureGapTracker(coverage);

    @Test
    void consecutiveIdsHaveNoGap() {
        assertEquals(0, tracker.observe("a", 1));
        assertEquals(0, tracker.observe("a", 2));
        assertEquals(0, tracker.observe("a", 3));
        assertEquals(List.of(), coverage.drain());
    }

    @Test
    void countsMissingCaptureIds() {
        tracker.observe("a", 1);
        assertEquals(3, tracker.observe("a", 5));
        assertEquals(0, tracker.observe("a", 6));
        assertEquals(1, tracker.observe("a", 8));
        assertEquals(List.of(new CoverageCounters.Delta(DAY, CoverageMetric.CAPTURE_ID_GAP, "a", 4)), coverage.drain());
    }

    @Test
    void theFirstIdOfAnInstanceIsABaseline() {
        assertEquals(0, tracker.observe("a", 40), "an earlier collector may have received 1..39");
        assertEquals(List.of(), coverage.drain());
    }

    @Test
    void aNewProxyInstanceResetsTracking() {
        tracker.observe("a", 10);
        assertEquals(0, tracker.observe("b", 1));
        assertEquals(1, tracker.observe("b", 3));
        assertEquals(List.of(new CoverageCounters.Delta(DAY, CoverageMetric.CAPTURE_ID_GAP, "b", 1)), coverage.drain());
    }

    @Test
    void anIdThatDoesNotIncreaseIsAProtocolError() {
        tracker.observe("a", 5);
        assertEquals(0, tracker.observe("a", 5));
        assertEquals(0, tracker.observe("a", 3));
        assertEquals(0, tracker.observe("a", 6), "the baseline did not move back");
        assertEquals(List.of(new CoverageCounters.Delta(DAY, CoverageMetric.IPC_PROTOCOL_ERRORS,
                                                        CoverageCounters.NO_DIMENSION, 2)),
                     coverage.drain());
    }
}
