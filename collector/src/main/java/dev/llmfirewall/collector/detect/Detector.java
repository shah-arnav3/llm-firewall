package dev.llmfirewall.collector.detect;

import dev.llmfirewall.collector.label.Segment;

import java.util.List;

/**
 * One detection technique. Implementations are thread-safe and must not keep segment
 * text beyond the call. A detector does not decide which sources it applies to: the
 * caller routes segments to detectors by {@link #category()}.
 */
public interface Detector {

    /** Stable name stored on findings, e.g. {@code regex-pii}, {@code prompt-guard-2}. */
    String name();

    /** Bumped whenever the detector's output for the same input can change. */
    int version();

    FindingCategory category();

    /**
     * @return hits in no particular order, possibly overlapping
     * @throws RuntimeException on a detector bug; the caller isolates it from other detectors
     */
    List<Detection> detect(Segment segment);
}
