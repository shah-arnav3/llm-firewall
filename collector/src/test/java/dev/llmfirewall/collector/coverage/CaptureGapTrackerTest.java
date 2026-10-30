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
    private static final long WINDOW = CaptureGapTracker.REORDER_WINDOW;

    private final CoverageCounters coverage = new CoverageCounters(10, CLOCK);
    private final CaptureGapTracker tracker = new CaptureGapTracker(coverage);

    private static CoverageCounters.Delta gap(String instance, long n) {
        return new CoverageCounters.Delta(DAY, CoverageMetric.CAPTURE_ID_GAP, instance, n);
    }

    @Test
    void consecutiveIdsHaveNoGap() {
        for (long id = 1; id <= 5; id++) {
            assertEquals(0, tracker.observe("a", id));
        }
        assertEquals(List.of(), coverage.drain());
    }

    @Test
    void neighboursArrivingOutOfOrderAreNotAGap() {
        tracker.observe("a", 1);
        tracker.observe("a", 3);
        tracker.observe("a", 2);
        tracker.observe("a", 5);
        tracker.observe("a", 4);
        tracker.observe("a", 5 + WINDOW);
        for (long id = 6; id < 5 + WINDOW; id++) {
            tracker.observe("a", id);
        }
        assertEquals(List.of(), coverage.drain(), "every id arrived in the end");
    }

    @Test
    void anIdStillMissingPastTheWindowIsAGap() {
        tracker.observe("a", 1);
        assertEquals(0, tracker.observe("a", 3), "2 may still arrive");
        assertEquals(0, tracker.observe("a", 2 + WINDOW));
        assertEquals(1, tracker.observe("a", 3 + WINDOW), "2 is now more than the window behind");
        assertEquals(List.of(gap("a", 1)), coverage.drain().stream()
            .filter(d -> d.metric() == CoverageMetric.CAPTURE_ID_GAP).toList());
    }

    @Test
    void aJumpLongerThanTheWindowCountsTheFarIdsAtOnce() {
        tracker.observe("a", 1);
        assertEquals(10, tracker.observe("a", 2 + WINDOW + 10), "ids 2..11 are already out of reach");
        assertEquals(List.of(gap("a", 10)), coverage.drain());
    }

    @Test
    void theFirstIdOfAnInstanceIsABaseline() {
        assertEquals(0, tracker.observe("a", 40), "an earlier collector may have received 1..39");
        assertEquals(List.of(), coverage.drain());
    }

    @Test
    void aNewInstanceCountsWhatTheOldOneStillOwed() {
        tracker.observe("a", 10);
        tracker.observe("a", 13);
        assertEquals(2, tracker.observe("b", 1), "11 and 12 can no longer arrive");
        assertEquals(0, tracker.observe("b", 3));
        assertEquals(List.of(gap("a", 2)), coverage.drain());
    }

    @Test
    void aRepeatedOrTooOldIdIsAProtocolError() {
        tracker.observe("a", 5);
        tracker.observe("a", 5);
        tracker.observe("a", 3);
        tracker.observe("a", 7);
        tracker.observe("a", 6);
        tracker.observe("a", 6);
        assertEquals(List.of(new CoverageCounters.Delta(DAY, CoverageMetric.IPC_PROTOCOL_ERRORS,
                                                        CoverageCounters.NO_DIMENSION, 3)),
                     coverage.drain());
    }
}
