package dev.llmfirewall.collector.label;

import static org.junit.jupiter.api.Assertions.assertEquals;

import dev.llmfirewall.collector.coverage.CoverageCounters;
import dev.llmfirewall.collector.label.adapters.AnthropicMessagesAdapter;
import dev.llmfirewall.collector.label.adapters.ClaudeAiUploadAdapter;
import dev.llmfirewall.collector.parse.JsonBodyParser;
import dev.llmfirewall.collector.parse.ParseException;
import dev.llmfirewall.collector.parse.ParsedBody;
import dev.llmfirewall.collector.parse.ParsedPart;
import dev.llmfirewall.collector.parse.SseReplyAssembler;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

class ClaudeAiUploadAdapterTest {

    private static final JsonBodyParser JSON = new JsonBodyParser(50, 1 << 20);
    private final ClaudeAiUploadAdapter adapter = new ClaudeAiUploadAdapter();

    private static ParsedPart text(int i, String text, ParsedPart.FileInfo file) {
        return new ParsedPart(ParsedPart.Kind.TEXT, "req:part[" + i + "]", "text/plain", null, text, null, file);
    }

    @Test
    void labelsFileTextAsAttachmentAndFieldsAsUnknown() throws ParseException {
        final ParsedBody body = new ParsedBody(List.of(
            text(0, "notes about the merger", new ParsedPart.FileInfo("txt", 22)),
            text(1, "attachment", null),
            new ParsedPart(ParsedPart.Kind.JSON, "req:part[2]", "application/json",
                           JSON.parse("{\"k\":\"v\"}".getBytes(StandardCharsets.UTF_8)), null, null),
            new ParsedPart(ParsedPart.Kind.BINARY_SKIPPED, "req:part[3]", "application/pdf", null, null, null,
                           new ParsedPart.FileInfo("pdf", 194_000)),
            text(4, "", new ParsedPart.FileInfo("txt", 0))), List.of(), false);
        final LabelResult result = adapter.labelRequest(body);
        assertEquals(List.of(new Segment(Source.ATTACHMENT, Direction.OUTBOUND, "notes about the merger", "req:part[0]"),
                             new Segment(Source.UNKNOWN, Direction.OUTBOUND, "attachment", "req:part[1]:text"),
                             new Segment(Source.UNKNOWN, Direction.OUTBOUND, "v", "req:part[2]:$.k")),
                     result.segments());
        assertEquals(Set.of("part(text)", "part(json)"), result.unknownFieldPaths());
    }

    @Test
    void labelsTheReplyAsUnknownWithoutDrift() throws ParseException {
        final ParsedBody reply = new ParsedBody(List.of(new ParsedPart(ParsedPart.Kind.JSON, "resp", "application/json",
            JSON.parse("{\"file_uuid\":\"f1\",\"preview\":\"notes\"}".getBytes(StandardCharsets.UTF_8)), null, null)),
            List.of(), false);
        final LabelResult result = adapter.labelResponse(reply);
        assertEquals(List.of("f1", "notes"), result.segments().stream().map(Segment::text).toList());
        assertEquals(Set.of(), result.unknownFieldPaths());
    }

    @Test
    void theLabelerRoutesUploadsHere() {
        final Labeler labeler = new Labeler(new AnthropicMessagesAdapter(new SseReplyAssembler(JSON)),
                                            new CoverageCounters(10, Clock.systemDefaultZone()));
        final EndpointKey upload = new EndpointRouter().route("claude.ai", "POST",
            "/api/organizations/02812373-138d-4a58-874b-33e46fa50871/conversations/f85e431c-3b8b-4dc7-aaa0-6ec211804df8"
            + "/wiggle/upload-file");
        final LabeledExchange labeled = labeler.label(upload, new ParsedBody(List.of(
            text(0, "file text", new ParsedPart.FileInfo("md", 9))), List.of(), false), ParsedBody.EMPTY);
        assertEquals("claude-ai.upload@1", labeled.adapterId());
        assertEquals(Source.ATTACHMENT, labeled.result().segments().get(0).source());
    }
}
