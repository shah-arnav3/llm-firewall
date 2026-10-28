package dev.llmfirewall.collector.coverage;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import dev.llmfirewall.collector.coverage.CoverageCounters.Delta;
import java.time.Clock;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

class CoverageCountersTest {

    private static final Clock CLOCK = Clock.fixed(Instant.parse("2026-10-27T23:30:00Z"), ZoneId.of("America/New_York"));
    private static final LocalDate DAY = LocalDate.of(2026, 10, 27);

    @Test
    void accumulatesPerMetricAndDimension() {
        final CoverageCounters c = new CoverageCounters(10, CLOCK);
        c.increment(CoverageMetric.IPC_PROTOCOL_ERRORS);
        c.add(CoverageMetric.CAPTURE_ID_GAP, "a", 3);
        c.increment(CoverageMetric.IPC_PROTOCOL_ERRORS);
        c.add(CoverageMetric.CAPTURE_ID_GAP, "b", 1);
        c.add(CoverageMetric.CAPTURE_ID_GAP, "a", 2);
        assertEquals(List.of(new Delta(DAY, CoverageMetric.IPC_PROTOCOL_ERRORS, "", 2),
                             new Delta(DAY, CoverageMetric.CAPTURE_ID_GAP, "a", 5),
                             new Delta(DAY, CoverageMetric.CAPTURE_ID_GAP, "b", 1)),
                     c.drain());
    }

    @Test
    void drainResets() {
        final CoverageCounters c = new CoverageCounters(10, CLOCK);
        c.increment(CoverageMetric.IPC_PROTOCOL_ERRORS);
        assertEquals(1, c.drain().size());
        assertEquals(List.of(), c.drain());
    }

    @Test
    void dimensionCardinalityIsCapped() {
        final CoverageCounters c = new CoverageCounters(2, CLOCK);
        c.increment(CoverageMetric.CAPTURE_ID_GAP, "a");
        c.increment(CoverageMetric.CAPTURE_ID_GAP, "b");
        c.increment(CoverageMetric.CAPTURE_ID_GAP, "c");
        c.increment(CoverageMetric.CAPTURE_ID_GAP, "d");
        c.increment(CoverageMetric.CAPTURE_ID_GAP, "a");
        c.increment(CoverageMetric.IPC_PROTOCOL_ERRORS);
        assertEquals(List.of(new Delta(DAY, CoverageMetric.CAPTURE_ID_GAP, "a", 2),
                             new Delta(DAY, CoverageMetric.CAPTURE_ID_GAP, "b", 1),
                             new Delta(DAY, CoverageMetric.CAPTURE_ID_GAP, CoverageCounters.OTHER_DIMENSION, 2),
                             new Delta(DAY, CoverageMetric.IPC_PROTOCOL_ERRORS, "", 1)),
                     c.drain(), "the cap is per metric");
        c.increment(CoverageMetric.CAPTURE_ID_GAP, "c");
        assertEquals(List.of(new Delta(DAY, CoverageMetric.CAPTURE_ID_GAP, "c", 1)), c.drain(),
                     "a drain starts the cap afresh");
    }

    @Test
    void rejectsANegativeAmountAndABadCap() {
        final CoverageCounters c = new CoverageCounters(1, CLOCK);
        assertThrows(IllegalArgumentException.class, () -> c.add(CoverageMetric.CAPTURE_ID_GAP, "a", -1));
        assertThrows(IllegalArgumentException.class, () -> new CoverageCounters(0, CLOCK));
    }

    @Test
    void isSafeToCountFromManyThreads() throws InterruptedException {
        final CoverageCounters c = new CoverageCounters(10, CLOCK);
        final List<Thread> threads = new ArrayList<>();
        for (int t = 0; t < 8; t++) {
            threads.add(Thread.ofPlatform().start(() -> {
                for (int i = 0; i < 10_000; i++) {
                    c.increment(CoverageMetric.IPC_PROTOCOL_ERRORS);
                }
            }));
        }
        for (Thread thread : threads) {
            thread.join();
        }
        assertEquals(List.of(new Delta(DAY, CoverageMetric.IPC_PROTOCOL_ERRORS, "", 80_000)), c.drain());
    }
}
