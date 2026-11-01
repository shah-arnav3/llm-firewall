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
import java.util.Arrays;
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

    private static byte[] upload(String... parts) {
        final StringBuilder body = new StringBuilder();
        for (String part : parts) {
            body.append("--b\r\n").append(part).append("\r\n");
        }
        return body.append("--b--\r\n").toString().getBytes(StandardCharsets.ISO_8859_1);
    }

    @Test
    void parsesAnUploadIntoFieldAndFileParts() {
        final byte[] data = upload(
            "Content-Disposition: form-data; name=\"purpose\"\r\n\r\nattachment",
            "Content-Disposition: form-data; name=\"meta\"\r\nContent-Type: application/json\r\n\r\n{\"a\":1}",
            "Content-Disposition: form-data; name=\"file\"; filename=\"Alice Smith notes.TXT\"\r\nContent-Type: text/plain\r\n\r\nhello",
            "Content-Disposition: form-data; name=\"file\"; filename=\"data\"\r\n\r\nplain utf-8",
            "Content-Disposition: form-data; name=\"file\"; filename=\"report.pdf\"\r\nContent-Type: application/pdf\r\n\r\n%PDF\u0000\u00ff");
        final ParsedBody parsed = registry.parseBody(body(data), "multipart/form-data; boundary=b", null, "req");
        assertEquals(List.of(), parsed.failures());
        assertFalse(parsed.incomplete());
        final List<ParsedPart> parts = parsed.parts();
        assertEquals(List.of("req:part[0]", "req:part[1]", "req:part[2]", "req:part[3]", "req:part[4]"),
                     parts.stream().map(ParsedPart::location).toList());
        assertEquals(ParsedPart.Kind.TEXT, parts.get(0).kind());
        assertEquals("attachment", parts.get(0).text());
        assertEquals(ParsedPart.Kind.JSON, parts.get(1).kind());
        assertEquals(new ParsedPart.FileInfo("txt", 5), parts.get(2).file());
        assertEquals("hello", parts.get(2).text());
        assertEquals(ParsedPart.Kind.TEXT, parts.get(3).kind(), "untyped valid UTF-8 is read as text");
        assertEquals("unknown", parts.get(3).file().fileType());
        assertEquals(ParsedPart.Kind.BINARY_SKIPPED, parts.get(4).kind());
        assertEquals(new ParsedPart.FileInfo("pdf", 6), parts.get(4).file());
        assertEquals(List.of("file:pdf"), counted(CoverageMetric.BODY_SKIPPED));
        assertFalse(parsed.toString().contains("Alice"), "filenames are not kept");
    }

    @Test
    void anUploadCutShortIsIncompleteAndABadOneFails() {
        final byte[] whole = upload("Content-Disposition: form-data; name=\"file\"; filename=\"a.txt\"\r\n\r\nsome text");
        final byte[] cut = Arrays.copyOf(whole, whole.length - 10);
        final ParsedBody parsed = registry.parseBody(body(cut), "multipart/form-data; boundary=b", null, "req");
        assertTrue(parsed.incomplete());
        assertEquals(1, parsed.parts().size());
        assertEquals(List.of("multipart:no_boundary"),
                     registry.parseBody(body(whole), "multipart/form-data", null, "req").failures());
    }
}
