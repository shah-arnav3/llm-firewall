package dev.llmfirewall.collector.detect;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.llmfirewall.collector.label.Direction;
import dev.llmfirewall.collector.label.EndpointKey;
import dev.llmfirewall.collector.label.Segment;
import dev.llmfirewall.collector.label.Source;
import java.util.Map;
import org.junit.jupiter.api.Test;

class SegmentDeduplicatorTest {

    private static EndpointKey conversation(String host, String conv) {
        return new EndpointKey("completion", host, "POST", "/api/organizations/{org}/chat_conversations/{conv}/completion",
                               Map.of("org", "o", "conv", conv), true);
    }

    private static final EndpointKey MESSAGES =
        new EndpointKey("messages_api", "api.anthropic.com", "POST", "/v1/messages", Map.of(), true);

    private static Segment text(String text) {
        return new Segment(Source.USER_TYPED, Direction.OUTBOUND, text, "req:$.prompt");
    }

    @Test
    void reportsARepeatAsADuplicate() {
        final SegmentDeduplicator dedup = new SegmentDeduplicator(10);
        assertTrue(dedup.firstSighting(MESSAGES, text("hello")));
        assertFalse(dedup.firstSighting(MESSAGES, text("hello")));
        assertTrue(dedup.firstSighting(MESSAGES, text("hello!")));
    }

    @Test
    void ignoresTheLocation() {
        final SegmentDeduplicator dedup = new SegmentDeduplicator(10);
        dedup.firstSighting(MESSAGES, text("hello"));
        // The same turn, one position later in the re-sent history.
        assertFalse(dedup.firstSighting(MESSAGES, new Segment(Source.USER_TYPED, Direction.OUTBOUND, "hello",
                                                              "req:$.messages[2].content")));
    }

    @Test
    void keysByHostConversationSourceAndDirection() {
        final SegmentDeduplicator dedup = new SegmentDeduplicator(10);
        assertTrue(dedup.firstSighting(conversation("claude.ai", "c1"), text("hello")));
        assertTrue(dedup.firstSighting(conversation("claude.ai", "c2"), text("hello")));
        assertTrue(dedup.firstSighting(conversation("other.example", "c1"), text("hello")));
        assertTrue(dedup.firstSighting(conversation("claude.ai", "c1"),
                                       new Segment(Source.ATTACHMENT, Direction.OUTBOUND, "hello", "req:$.prompt")));
        assertTrue(dedup.firstSighting(conversation("claude.ai", "c1"),
                                       new Segment(Source.USER_TYPED, Direction.INBOUND, "hello", "req:$.prompt")));
        assertFalse(dedup.firstSighting(conversation("claude.ai", "c2"), text("hello")));
    }

    @Test
    void evictsTheLeastRecentlySeen() {
        final SegmentDeduplicator dedup = new SegmentDeduplicator(2);
        dedup.firstSighting(MESSAGES, text("a"));
        dedup.firstSighting(MESSAGES, text("b"));
        assertFalse(dedup.firstSighting(MESSAGES, text("a")));  // Now b is the eldest.
        dedup.firstSighting(MESSAGES, text("c"));               // Evicts b.
        assertFalse(dedup.firstSighting(MESSAGES, text("a")));
        assertTrue(dedup.firstSighting(MESSAGES, text("b")));
    }

    @Test
    void rejectsANonPositiveSize() {
        assertThrows(IllegalArgumentException.class, () -> new SegmentDeduplicator(0));
    }
}
