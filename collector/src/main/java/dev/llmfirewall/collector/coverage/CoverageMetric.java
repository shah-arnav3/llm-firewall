package dev.llmfirewall.collector.coverage;

/**
 * Every coverage counter. The dimension (if any) is given in brackets. Together they
 * make gaps in what was logged visible.
 */
public enum CoverageMetric {
    // From the proxy's ProxyStats, as deltas [proxy_instance_id]
    PROXY_CAPTURES_DROPPED_QUEUE_FULL,
    PROXY_CAPTURES_DROPPED_IPC_UNAVAILABLE,
    PROXY_REQUEST_BODIES_TRUNCATED,
    PROXY_RESPONSE_BODIES_TRUNCATED,
    PROXY_WS_MESSAGES_TRUNCATED,
    PROXY_TUNNELS_UNSCOPED,
    PROXY_TUNNELS_SCOPED_NO_CERT,
    PROXY_TUNNELS_UPSTREAM_VERIFY_FAILED,
    PROXY_TUNNELS_CLIENT_TLS_BREAKER,
    PROXY_CLIENT_TLS_HANDSHAKE_FAILURES,
    PROXY_HTTP_PARSE_ERRORS,
    PROXY_WS_DECODE_ERRORS,
    PROXY_NON_CONNECT_REJECTED,

    // Observed by the collector
    /** Captures missing from the stream, by capture_id [proxy_instance_id]. Independent of the proxy's own counters. */
    CAPTURE_ID_GAP,
    /** Captures received from the proxy. */
    CAPTURES_RECEIVED,
    /** Streams that break the protocol: no hello first, an unknown version, a bad or oversized frame, or a capture_id going backwards. */
    IPC_PROTOCOL_ERRORS,
    /** Connections refused because the peer is another user. */
    IPC_PEER_REJECTED,
    /** Bodies that could not be decoded or parsed [failure code]. */
    PARSE_FAILURE,
    /** Bodies of a media type that is not parsed [media type]. */
    BODY_SKIPPED,
    /** JSON key paths and value types seen on a routed endpoint, never values [endpoint part:path:type]. */
    SCHEMA_SURVEY,
    /** Exchanges on an endpoint no adapter knows, so all their text is UNKNOWN [host method path_template]. */
    UNKNOWN_ENDPOINT,
    /** Fields outside an adapter's schema, labeled UNKNOWN [adapter_id json_key_path]. */
    SCHEMA_DRIFT,
    /** Adapters that threw; the fallback labeled the exchange instead [adapter_id]. */
    ADAPTER_FAILURE,
}
