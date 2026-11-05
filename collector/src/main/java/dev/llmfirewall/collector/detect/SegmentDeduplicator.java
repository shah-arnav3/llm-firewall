package dev.llmfirewall.collector.detect;

import dev.llmfirewall.collector.label.Direction;
import dev.llmfirewall.collector.label.EndpointKey;
import dev.llmfirewall.collector.label.Segment;
import dev.llmfirewall.collector.label.Source;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Suppresses re-scanning of text that has already been scanned: Messages API clients
 * re-send the whole history on every turn. A bounded LRU is keyed by host,
 * conversation, source, direction and the SHA-256 of the segment text. The
 * conversation is the {@code conv} path parameter; endpoints without one, such as
 * {@code /v1/messages}, share one key per host, so identical text in two of their
 * conversations is scanned once. The cache is in memory only, so after a restart a
 * segment may be scanned once more.
 */
public final class SegmentDeduplicator {

    private record Key(String host, String conversation, Source source, Direction direction, String sha256) {}

    private final Map<Key, Boolean> seen;

    /** @throws IllegalArgumentException if {@code maxEntries} is not positive */
    public SegmentDeduplicator(int maxEntries) {
        if (maxEntries <= 0) {
            throw new IllegalArgumentException("maxEntries must be positive: " + maxEntries);
        }
        seen = new LinkedHashMap<>(16, 0.75f, true) {
            private static final long serialVersionUID = 1L;

            @Override
            protected boolean removeEldestEntry(Map.Entry<Key, Boolean> eldest) {
                return size() > maxEntries;
            }
        };
    }

    /**
     * Thread-safe.
     *
     * @return true if this segment was not seen before (and records it), false if it is a duplicate
     */
    public boolean firstSighting(EndpointKey endpoint, Segment segment) {
        final Key key = new Key(endpoint.host(), endpoint.pathParams().getOrDefault("conv", ""),
                                segment.source(), segment.direction(), sha256(segment.text()));
        synchronized (seen) {
            return seen.put(key, Boolean.TRUE) == null;
        }
    }

    private static String sha256(String text) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(text.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new AssertionError("every JVM has SHA-256", e);
        }
    }
}
