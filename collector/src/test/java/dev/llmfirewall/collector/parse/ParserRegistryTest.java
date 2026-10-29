package dev.llmfirewall.collector.parse;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.protobuf.ByteString;
import dev.llmfirewall.collector.coverage.CoverageCounters;
import dev.llmfirewall.collector.coverage.CoverageCounters.Delta;
import dev.llmfirewall.collector.coverage.CoverageMetric;
import dev.llmfirewall.proto.v1.Body;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.List;
import java.util.zip.GZIPOutputStream;
import org.junit.jupiter.api.Test;

class ParserRegistryTest {

    private final CoverageCounters coverage = new CoverageCounters(10, Clock.systemDefaultZone());
    private final ParserRegistry registry = new ParserRegistry(new ContentDecoder(1 << 20), new JsonBodyParser(50, 1 << 20),
                                                               new SseStreamParser(), coverage);

    private static Body body(byte[] data) {
        return Body.newBuilder().setData(ByteString.copyFrom(data)).setTotalBytes(data.length).build();
    }

    private static Body body(String data) {
        return body(data.getBytes(StandardCharsets.UTF_8));
    }

    private static byte[] gzip(String text) throws IOException {
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (GZIPOutputStream gz = new GZIPOutputStream(out)) {
            gz.write(text.getBytes(StandardCharsets.UTF_8));
        }
        return out.toByteArray();
    }

    private List<String> counted(CoverageMetric metric) {
        return coverage.drain().stream().filter(d -> d.metric() == metric).map(Delta::dimension).toList();
    }

    @Test
    void parsesAGzippedJsonBody() throws IOException {
        final ParsedBody parsed = registry.parseBody(body(gzip("{\"prompt\":\"hi\"}")), "application/json; charset=utf-8",
                                                     "gzip", "req");
        assertEquals(1, parsed.parts().size());
        final ParsedPart part = parsed.parts().get(0);
        assertEquals(ParsedPart.Kind.JSON, part.kind());
        assertEquals("req", part.location());
        assertEquals("application/json", part.mediaType());
        assertEquals("hi", part.json().get("prompt").asText());
        assertFalse(parsed.incomplete());
        assertEquals(List.of(), parsed.failures());
    }

    @Test
    void splitsAnEventStream() {
        final ParsedPart part = registry.parseBody(body("data: a\n\ndata: b\n\n"), "text/event-stream", null, "resp")
            .parts().get(0);
        assertEquals(ParsedPart.Kind.SSE_STREAM, part.kind());
        assertEquals(List.of("a", "b"), part.sseEvents().stream().map(SseStreamParser.SseEvent::data).toList());
    }

    @Test
    void readsOtherTextAsUtf8() {
        final ParsedPart part = registry.parseBody(body("café"), "Text/Plain", null, "resp").parts().get(0);
        assertEquals(ParsedPart.Kind.TEXT, part.kind());
        assertEquals("café", part.text());
    }

    @Test
    void skipsAndCountsOtherMediaTypes() {
        assertEquals(ParsedPart.Kind.BINARY_SKIPPED,
                     registry.parseBody(body(new byte[] {1, 2}), "image/png", null, "resp").parts().get(0).kind());
        assertEquals(ParsedPart.Kind.BINARY_SKIPPED, registry.parseBody(body("x"), null, null, "resp").parts().get(0).kind());
        assertEquals(List.of("image/png", "<none>"), counted(CoverageMetric.BODY_SKIPPED));
    }

    @Test
    void anOmittedOrEmptyBodyGivesNothing() {
        assertEquals(ParsedBody.EMPTY, registry.parseBody(Body.newBuilder().setOmitted(true).setTotalBytes(9).build(),
                                                          "application/json", null, "req"));
        assertEquals(ParsedBody.EMPTY, registry.parseBody(Body.getDefaultInstance(), "application/json", null, "req"));
        assertEquals(List.of(), coverage.drain());
    }

    @Test
    void countsDecodeAndParseFailures() {
        final ParsedBody corrupt = registry.parseBody(body("not gzip"), "application/json", "gzip", "req");
        assertEquals(new ParsedBody(List.of(), List.of("decode:corrupt"), false), corrupt);
        final ParsedBody bad = registry.parseBody(body("{\"a\":"), "application/json", null, "req");
        assertEquals(List.of("json:syntax"), bad.failures());
        assertEquals(List.of("decode:corrupt", "json:syntax"), counted(CoverageMetric.PARSE_FAILURE));
    }

    @Test
    void aTruncatedCaptureIsIncomplete() {
        final Body cut = body("data: a\n\ndata: b").toBuilder().setTotalBytes(1000).setTruncated(true).build();
        final ParsedBody parsed = registry.parseBody(cut, "text/event-stream", null, "resp");
        assertTrue(parsed.incomplete());
        assertEquals(2, parsed.parts().get(0).sseEvents().size(), "the partial event is kept");
        assertTrue(registry.parseBody(cut.toBuilder().setData(ByteString.copyFromUtf8("{\"a\":")).build(),
                                      "application/json", null, "req").incomplete(),
                   "a failed parse of a truncated body is still marked incomplete");
    }
}
