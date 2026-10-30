package dev.llmfirewall.collector.label;

import static org.junit.jupiter.api.Assertions.assertEquals;

import dev.llmfirewall.collector.label.adapters.AnthropicMessagesAdapter;
import dev.llmfirewall.collector.label.adapters.ClaudeAiCompletionAdapter;
import dev.llmfirewall.collector.parse.JsonBodyParser;
import dev.llmfirewall.collector.parse.ParseException;
import dev.llmfirewall.collector.parse.ParsedBody;
import dev.llmfirewall.collector.parse.ParsedPart;
import dev.llmfirewall.collector.parse.SseReplyAssembler;
import dev.llmfirewall.collector.parse.SseStreamParser;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.Test;

class ClaudeAiCompletionAdapterTest {

    private static final JsonBodyParser JSON = new JsonBodyParser(100, 1 << 20);
    private final ClaudeAiCompletionAdapter adapter =
        new ClaudeAiCompletionAdapter(new AnthropicMessagesAdapter(new SseReplyAssembler(JSON)));

    private static ParsedBody request(String json) throws ParseException {
        return new ParsedBody(List.of(new ParsedPart(ParsedPart.Kind.JSON, "req", "application/json",
            JSON.parse(json.getBytes(StandardCharsets.UTF_8)), null, null)), List.of(), false);
    }

    private static Segment out(Source source, String text, String location) {
        return new Segment(source, Direction.OUTBOUND, text, location);
    }

    @Test
    void labelsTheSurveyedRequestShape() throws ParseException {
        final LabelResult result = adapter.labelRequest(request("""
            {"prompt":"what is in this file?","timezone":"America/New_York","locale":"en-US","model":"claude-opus-5-5",
             "effort":"high","thinking_mode":"auto","rendering_mode":"messages","completion_request_id":"r1",
             "files":["f85e431c-3b8b-4dc7-aaa0-6ec211804df8"],
             "attachments":[{"file_name":"notes.txt","extracted_content":"meeting notes"}],
             "sync_sources":[{"title":"Drive doc"}],
             "turn_message_uuids":{"human_message_uuid":"h","assistant_message_uuid":"a"},
             "create_conversation_params":{"name":"","model":"claude-opus-5-5","is_temporary":false,"compass_mode":null},
             "tools":[{"type":"mcp","name":"search","description":"Searches the wiki","mcp_server_url":"https://mcp.example",
                       "needs_approval":true,"input_schema":{"properties":{"q":{"description":"query"}}}}]}
            """));
        assertEquals(List.of(out(Source.USER_TYPED, "what is in this file?", "req:$.prompt"),
                             out(Source.ATTACHMENT, "notes.txt", "req:$.attachments[0].file_name"),
                             out(Source.ATTACHMENT, "meeting notes", "req:$.attachments[0].extracted_content"),
                             out(Source.UNKNOWN, "Drive doc", "req:$.sync_sources[0].title"),
                             out(Source.UNKNOWN, "Searches the wiki", "req:$.tools[0].description"),
                             out(Source.UNKNOWN, "query", "req:$.tools[0].input_schema.properties.q.description")),
                     result.segments());
        assertEquals(Set.of(), result.unknownFieldPaths());
        assertEquals(new LabelResult.Attributes(Optional.of("claude-opus-5-5"), false), result.attributes());
    }

    @Test
    void labelsAndReportsFieldsOutsideTheSchema() throws ParseException {
        final LabelResult result = adapter.labelRequest(request("""
            {"prompt":"hi","paste":"pasted text","create_conversation_params":{"name":"Trip plans","mood":"x"},
             "tools":[{"name":"t","hint":"h"}]}
            """));
        assertEquals(List.of(out(Source.USER_TYPED, "hi", "req:$.prompt"),
                             out(Source.UNKNOWN, "pasted text", "req:$.paste"),
                             out(Source.UNKNOWN, "Trip plans", "req:$.create_conversation_params.name"),
                             out(Source.UNKNOWN, "x", "req:$.create_conversation_params.mood"),
                             out(Source.UNKNOWN, "h", "req:$.tools[0].hint")),
                     result.segments());
        assertEquals(Set.of("$.paste", "$.create_conversation_params.mood", "$.tools[].hint"), result.unknownFieldPaths());
    }

    @Test
    void labelsRepliesWithTheMessagesGrammar() {
        final String stream = "data: {\"type\":\"conversation_ready\",\"created_at\":\"t\"}\n\n"
            + "data: {\"type\":\"message_start\",\"message\":{\"model\":\"claude-opus-5-5\"}}\n\n"
            + "data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n"
            + "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Hello\"}}\n\n"
            + "data: {\"type\":\"message_limit\",\"message_limit\":{\"type\":\"within_limit\"}}\n\n";
        final ParsedBody body = new ParsedBody(List.of(new ParsedPart(ParsedPart.Kind.SSE_STREAM, "resp", "text/event-stream",
            null, null, new SseStreamParser().events(stream.getBytes(StandardCharsets.UTF_8)))), List.of(), false);
        assertEquals(List.of(new Segment(Source.MODEL_OUTPUT, Direction.INBOUND, "Hello", "resp:sse:block[0]")),
                     adapter.labelResponse(body).segments());
    }
}
