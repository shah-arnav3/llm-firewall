package dev.llmfirewall.collector.coverage;

import java.util.TreeSet;

/**
 * Detects dropped captures independently of the proxy's own counters. A proxy numbers
 * its captures 1, 2, 3, ... for its whole life, including ones it drops, so a capture_id
 * that never arrives means a capture was lost; each one is added to CAPTURE_ID_GAP under
 * the proxy_instance_id. That includes captures dropped while the collector was
 * unreachable, as long as this collector process saw the proxy before.
 *
 * <p>The proxy assigns ids on several I/O threads just before queueing, so neighbouring
 * captures can arrive slightly out of order. An id skipped over therefore waits: it counts
 * as a gap only once an id more than {@link #REORDER_WINDOW} above it has arrived, or when
 * a new proxy instance appears. Ids still waiting when the collector stops are not counted.
 *
 * <p>Only the current proxy instance is remembered. The first capture_id seen from an
 * instance is a baseline, not a gap, because an earlier collector process may have
 * received the ones before it. An id that arrives twice, or below the window, breaks the
 * stream's rules; it counts as IPC_PROTOCOL_ERRORS.
 *
 * <p>Not thread-safe: the receiver thread is its only caller.
 */
public final class CaptureGapTracker {

    /** How far behind the highest id seen a capture may still arrive. */
    public static final long REORDER_WINDOW = 1024;

    private final CoverageCounters coverage;
    private final TreeSet<Long> waiting = new TreeSet<>();
    private String instanceId;
    private long highest;

    public CaptureGapTracker(CoverageCounters coverage) {
        this.coverage = coverage;
    }

    /** @return the number of captures this call confirmed as lost (0 normally) */
    public long observe(String proxyInstanceId, long captureId) {
        if (!proxyInstanceId.equals(instanceId)) {
            final long lost = waiting.size();
            countGaps(lost);
            waiting.clear();
            instanceId = proxyInstanceId;
            highest = captureId;
            return lost;
        }
        long lost = 0;
        if (captureId > highest) {
            // Ids beyond the window below captureId are lost already; the rest may still arrive.
            final long firstKept = Math.max(highest + 1, captureId - REORDER_WINDOW);
            lost += firstKept - (highest + 1);
            for (long id = firstKept; id < captureId; id++) {
                waiting.add(id);
            }
            highest = captureId;
        } else if (!waiting.remove(captureId)) {
            coverage.increment(CoverageMetric.IPC_PROTOCOL_ERRORS);
        }
        while (!waiting.isEmpty() && highest - waiting.first() > REORDER_WINDOW) {
            waiting.pollFirst();
            lost++;
        }
        countGaps(lost);
        return lost;
    }

    private void countGaps(long lost) {
        if (lost > 0) {
            coverage.add(CoverageMetric.CAPTURE_ID_GAP, instanceId, lost);
        }
    }
}
