package dev.llmfirewall.collector.coverage;

/**
 * Detects dropped captures independently of the proxy's own counters. A proxy numbers
 * its captures 1, 2, 3, ... for its whole life, including ones it drops, so a jump from
 * n to m &gt; n+1 means m - n - 1 captures never arrived; they are added to
 * CAPTURE_ID_GAP under the proxy_instance_id. That includes captures dropped while the
 * collector was unreachable, as long as this collector process saw the proxy before.
 *
 * <p>Only the current proxy instance is remembered. The first capture_id seen from an
 * instance is a baseline, not a gap, because an earlier collector process may have
 * received the ones before it. A capture_id that does not increase breaks the ordered
 * stream; it counts as IPC_PROTOCOL_ERRORS and does not move the baseline.
 *
 * <p>Not thread-safe: the receiver thread is its only caller.
 */
public final class CaptureGapTracker {

    private final CoverageCounters coverage;
    private String instanceId;
    private long lastCaptureId;

    public CaptureGapTracker(CoverageCounters coverage) {
        this.coverage = coverage;
    }

    /** @return the number of captures missing just before this one (0 normally) */
    public long observe(String proxyInstanceId, long captureId) {
        if (!proxyInstanceId.equals(instanceId)) {
            instanceId = proxyInstanceId;
            lastCaptureId = captureId;
            return 0;
        }
        if (captureId <= lastCaptureId) {
            coverage.increment(CoverageMetric.IPC_PROTOCOL_ERRORS);
            return 0;
        }
        final long gap = captureId - lastCaptureId - 1;
        lastCaptureId = captureId;
        if (gap > 0) {
            coverage.add(CoverageMetric.CAPTURE_ID_GAP, proxyInstanceId, gap);
        }
        return gap;
    }
}
