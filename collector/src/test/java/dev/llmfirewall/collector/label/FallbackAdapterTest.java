package dev.llmfirewall.collector.label;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.fasterxml.jackson.databind.JsonNode;
import dev.llmfirewall.collector.label.adapters.FallbackAdapter;
import dev.llmfirewall.collector.parse.JsonBodyParser;
import dev.llmfirewall.collector.parse.ParseException;
import dev.llmfirewall.collector.parse.ParsedBody;
import dev.llmfirewall.collector.parse.ParsedPart;
import dev.llmfirewall.collector.parse.SseStreamParser;
import java.nio.charset.StandardCharsets;
import java.util.List;
import org.junit.jupiter.api.Test;

class FallbackAdapterTest {

    private final FallbackAdapter fallback = new FallbackAdapter();

    private static JsonNode json(String text) throws ParseException {
        return new JsonBodyParser(50, 1 << 20).parse(text.getBytes(StandardCharsets.UTF_8));
    }

    private static ParsedBody body(ParsedPart... parts) {
        return new ParsedBody(List.of(parts), List.of(), false);
    }

    private static Segment unknown(Direction direction, String text, String location) {
        return new Segment(Source.UNKNOWN, direction, text, location);
    }

    @Test
    void emitsEveryJsonStringWithItsPath() throws ParseException {
        final ParsedPart part = new ParsedPart(ParsedPart.Kind.JSON, "req", "application/json",
            json("{\"prompt\":\"hi\",\"n\":3,\"ok\":true,\"empty\":\"\",\"files\":[{\"name\":\"a.txt\"},\"b\"],\"x\":null}"),
            null, null);
        assertEquals(List.of(unknown(Direction.OUTBOUND, "hi", "req:$.prompt"),
                             unknown(Direction.OUTBOUND, "a.txt", "req:$.files[0].name"),
                             unknown(Direction.OUTBOUND, "b", "req:$.files[1]")),
                     fallback.segments(body(part), Direction.OUTBOUND));
    }

    @Test
    void scansKeysThatAreNotPlainIdentifiersAndKeepsThemOutOfPaths() throws ParseException {
        final ParsedPart part = new ParsedPart(ParsedPart.Kind.JSON, "resp", "application/json",
            json("{\"alice@example.com\":{\"note\":\"x\"},\"ok_key-1\":\"y\"}"), null, null);
        assertEquals(List.of(unknown(Direction.INBOUND, "alice@example.com", "resp:$[*](key)"),
                             unknown(Direction.INBOUND, "x", "resp:$[*].note"),
                             unknown(Direction.INBOUND, "y", "resp:$.ok_key-1")),
                     fallback.segments(body(part), Direction.INBOUND));
    }

    @Test
    void emitsTextPartsAndEachSseEvent() {
        final ParsedPart text = new ParsedPart(ParsedPart.Kind.TEXT, "req", "text/plain", null, "plain words", null);
        final ParsedPart sse = new ParsedPart(ParsedPart.Kind.SSE_STREAM, "resp", "text/event-stream", null, null,
            new SseStreamParser().events("data: one\n\ndata: two\n\n".getBytes(StandardCharsets.UTF_8)));
        assertEquals(List.of(unknown(Direction.OUTBOUND, "plain words", "req:text"),
                             unknown(Direction.OUTBOUND, "one", "resp:sse[0]"),
                             unknown(Direction.OUTBOUND, "two", "resp:sse[1]")),
                     fallback.segments(body(text, sse), Direction.OUTBOUND));
    }

    @Test
    void skippedAndEmptyBodiesGiveNothing() {
        final ParsedPart skipped = new ParsedPart(ParsedPart.Kind.BINARY_SKIPPED, "resp", "image/png", null, null, null);
        assertEquals(List.of(), fallback.segments(body(skipped), Direction.INBOUND));
        assertEquals(List.of(), fallback.segments(ParsedBody.EMPTY, Direction.INBOUND));
    }

    @Test
    void keyPathsUseDotsOnlyForPlainKeys() {
        assertEquals(".model", FallbackAdapter.keyPath("model"));
        assertEquals("[*]", FallbackAdapter.keyPath("has space"));
        assertEquals("[*]", FallbackAdapter.keyPath("k".repeat(65)));
        assertEquals("[*]", FallbackAdapter.keyPath(""));
    }
}
