package dev.llmfirewall.collector.parse;

import static org.junit.jupiter.api.Assertions.assertEquals;

import dev.llmfirewall.collector.parse.SseStreamParser.SseEvent;
import java.nio.charset.StandardCharsets;
import java.util.List;
import org.junit.jupiter.api.Test;

class SseStreamParserTest {

    private static List<SseEvent> parse(String body) {
        return new SseStreamParser().events(body.getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void parsesAnthropicStyleEvents() {
        final List<SseEvent> events = parse(
            "event: message_start\ndata: {\"type\":\"message_start\"}\n\n"
            + "event: content_block_delta\ndata: {\"delta\":{\"text\":\"Hi\"}}\n\n");
        assertEquals(List.of(new SseEvent(0, "message_start", "{\"type\":\"message_start\"}", "", true),
                             new SseEvent(1, "content_block_delta", "{\"delta\":{\"text\":\"Hi\"}}", "", true)),
                     events);
    }

    @Test
    void joinsMultiLineDataFields() {
        assertEquals("a\nb\n\nc", parse("data: a\ndata: b\ndata\ndata: c\n\n").get(0).data());
    }

    @Test
    void acceptsCrLfLfAndCrLineEndings() {
        for (String body : new String[] {"data: x\r\n\r\ndata: y\r\n\r\n", "data: x\n\ndata: y\n\n", "data: x\r\rdata: y\r\r",
                                         "data: x\r\n\ndata: y\r\r"}) {
            final List<SseEvent> events = parse(body);
            assertEquals(List.of("x", "y"), events.stream().map(SseEvent::data).toList(), body);
        }
    }

    @Test
    void removesOnlyOneSpaceAfterTheColon() {
        assertEquals(" two", parse("data:  two\n\n").get(0).data());
        assertEquals("none", parse("data:none\n\n").get(0).data());
    }

    @Test
    void ignoresCommentsRetryAndUnknownFields() {
        assertEquals(List.of(new SseEvent(0, "message", "x", "", true)),
                     parse(": keep-alive\nretry: 100\nfoo: bar\ndata: x\n\n:ping\n\n"));
    }

    @Test
    void anEventWithoutDataIsNotEmitted() {
        assertEquals(List.of(new SseEvent(0, "message", "x", "", true)), parse("event: ping\n\ndata: x\n\n"));
    }

    @Test
    void theLastEventIdCarriesOver() {
        final List<SseEvent> events = parse("id: 7\ndata: a\n\ndata: b\n\nid: bad\0id\ndata: c\n\n");
        assertEquals(List.of("7", "7", "7"), events.stream().map(SseEvent::id).toList());
    }

    @Test
    void marksTrailingPartialEventIncomplete() {
        assertEquals(List.of(new SseEvent(0, "message", "done", "", true),
                             new SseEvent(1, "content_block_delta", "{\"delta\":{\"te", "", false)),
                     parse("data: done\n\nevent: content_block_delta\ndata: {\"delta\":{\"te"));
        assertEquals(List.of(false), parse("data: whole line\n").stream().map(SseEvent::complete).toList(),
                     "a final line without the blank line after it");
    }

    @Test
    void dropsALeadingBomAndReplacesInvalidUtf8() {
        final byte[] body = {(byte) 0xEF, (byte) 0xBB, (byte) 0xBF, 'd', 'a', 't', 'a', ':', ' ', (byte) 0xFF, '\n', '\n'};
        assertEquals(List.of(new SseEvent(0, "message", "�", "", true)), new SseStreamParser().events(body));
    }

    @Test
    void anEmptyBodyHasNoEvents() {
        assertEquals(List.of(), parse(""));
    }
}
