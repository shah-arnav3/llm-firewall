package dev.llmfirewall.collector.coverage;

/**
 * Every coverage counter. The dimension (if any) is given in brackets. Together they
 * make gaps in what was logged visible.
 */
public enum CoverageMetric {
    /** Captures missing from the stream, by capture_id [proxy_instance_id]. Independent of the proxy's own counters. */
    CAPTURE_ID_GAP,
    /** Frames that break the stream's rules, such as a capture_id going backwards. */
    IPC_PROTOCOL_ERRORS,
}
