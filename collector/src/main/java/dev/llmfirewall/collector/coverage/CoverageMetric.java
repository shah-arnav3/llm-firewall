package dev.llmfirewall.collector.coverage;

/**
 * Every coverage counter. The dimension (if any) is given in brackets. Together they
 * make gaps in what was logged visible.
 */
public enum CoverageMetric {
    /** Captures missing from the stream, by capture_id [proxy_instance_id]. Independent of the proxy's own counters. */
    CAPTURE_ID_GAP,
    /** Captures received from the proxy. */
    CAPTURES_RECEIVED,
    /** Streams that break the protocol: no hello first, an unknown version, a bad or oversized frame, or a capture_id going backwards. */
    IPC_PROTOCOL_ERRORS,
    /** Connections refused because the peer is another user. */
    IPC_PEER_REJECTED,
}
