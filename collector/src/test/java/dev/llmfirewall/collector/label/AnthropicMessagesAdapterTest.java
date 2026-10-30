package dev.llmfirewall.collector.label;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.llmfirewall.collector.label.adapters.AnthropicMessagesAdapter;
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

class AnthropicMessagesAdapterTest {

    private static final JsonBodyParser JSON = new JsonBodyParser(100, 1 << 20);
    private final AnthropicMessagesAdapter adapter = new AnthropicMessagesAdapter(new SseReplyAssembler(JSON));

    private static ParsedBody request(String json) throws ParseException {
        return new ParsedBody(List.of(new ParsedPart(ParsedPart.Kind.JSON, "req", "application/json",
            JSON.parse(json.getBytes(StandardCharsets.UTF_8)), null, null)), List.of(), false);
    }

    private static Segment out(Source source, String text, String location) {
        return new Segment(source, Direction.OUTBOUND, text, location);
    }

    @Test
    void labelsAClaudeCodeRequest() throws ParseException {
        final LabelResult result = adapter.labelRequest(request("""
            {"model":"claude-opus-5-5","max_tokens":32000,"stream":true,"metadata":{"user_id":"u1"},
             "system":[{"type":"text","text":"You are Claude Code.","cache_control":{"type":"ephemeral"}}],
             "messages":[
               {"role":"user","content":"fix the bug"},
               {"role":"assistant","content":[
                  {"type":"thinking","thinking":"Look at main.c","signature":"EqQB"},
                  {"type":"text","text":"Reading it."},
                  {"type":"tool_use","id":"t1","name":"Read","input":{"path":"main.c"}}]},
               {"role":"user","content":[
                  {"type":"tool_result","tool_use_id":"t1","is_error":false,"content":"int main() {}"},
                  {"type":"tool_result","tool_use_id":"t2","content":[{"type":"text","text":"second"},{"type":"tool_reference","tool_name":"Grep"}]},
                  {"type":"text","text":"<system-reminder>be careful</system-reminder>"}]}],
             "tools":[{"name":"Read","description":"Reads a file","input_schema":{"type":"object",
                       "properties":{"path":{"type":"string","description":"File to read"}}}}],
             "safeguards":[{"classifier_context":{"git_state":{"cwd":"/Users/me/repo"}}}]}
            """));
        assertEquals(List.of(
            out(Source.UNKNOWN, "You are Claude Code.", "req:$.system[0].text"),
            out(Source.UNKNOWN, "fix the bug", "req:$.messages[0].content"),
            out(Source.MODEL_OUTPUT, "Look at main.c", "req:$.messages[1].content[0].thinking"),
            out(Source.MODEL_OUTPUT, "Reading it.", "req:$.messages[1].content[1].text"),
            out(Source.MODEL_OUTPUT, "main.c", "req:$.messages[1].content[2].input.path"),
            out(Source.TOOL_RESULT, "int main() {}", "req:$.messages[2].content[0].content"),
            out(Source.TOOL_RESULT, "second", "req:$.messages[2].content[1].content[0].text"),
            out(Source.UNKNOWN, "<system-reminder>be careful</system-reminder>", "req:$.messages[2].content[2].text"),
            out(Source.UNKNOWN, "Reads a file", "req:$.tools[0].description"),
            out(Source.UNKNOWN, "object", "req:$.tools[0].input_schema.type"),
            out(Source.UNKNOWN, "string", "req:$.tools[0].input_schema.properties.path.type"),
            out(Source.UNKNOWN, "File to read", "req:$.tools[0].input_schema.properties.path.description"),
            out(Source.UNKNOWN, "/Users/me/repo", "req:$.safeguards[0].classifier_context.git_state.cwd")),
            result.segments());
        assertEquals(Set.of(), result.unknownFieldPaths());
        assertEquals(new LabelResult.Attributes(Optional.of("claude-opus-5-5"), true), result.attributes());
    }

    @Test
    void acceptsAPlainStringSystemPromptAndAssistantString() throws ParseException {
        assertEquals(List.of(out(Source.UNKNOWN, "Be brief.", "req:$.system"),
                             out(Source.MODEL_OUTPUT, "Done.", "req:$.messages[0].content")),
                     adapter.labelRequest(request("{\"system\":\"Be brief.\",\"messages\":[{\"role\":\"assistant\",\"content\":\"Done.\"}]}"))
                         .segments());
    }

    @Test
    void labelsTextDocumentsAndSkipsImageData() throws ParseException {
        final LabelResult result = adapter.labelRequest(request("""
            {"messages":[{"role":"user","content":[
              {"type":"document","source":{"type":"text","media_type":"text/plain","data":"contract text"}},
              {"type":"document","source":{"type":"base64","media_type":"application/pdf","data":"JVBERi0x"}},
              {"type":"image","source":{"type":"base64","media_type":"image/png","data":"iVBORw0K"}}]}]}
            """));
        assertEquals(List.of(out(Source.ATTACHMENT, "contract text", "req:$.messages[0].content[0].source.data")),
                     result.segments());
        assertFalse(result.attributes().hasToolResults());
    }

    @Test
    void labelsAndReportsFieldsOutsideTheSchema() throws ParseException {
        final LabelResult result = adapter.labelRequest(request("""
            {"model":"m","new_field":{"note":"hidden"},"messages":[{"role":"user","extra":"x",
              "content":[{"type":"text","text":"hi","annotation":"y"},{"type":"video","frames":"z"}]}],
             "tools":[{"name":"T","hint":"h"}]}
            """));
        assertEquals(List.of(out(Source.UNKNOWN, "hidden", "req:$.new_field.note"),
                             out(Source.UNKNOWN, "x", "req:$.messages[0].extra"),
                             out(Source.UNKNOWN, "hi", "req:$.messages[0].content[0].text"),
                             out(Source.UNKNOWN, "y", "req:$.messages[0].content[0].annotation"),
                             out(Source.UNKNOWN, "z", "req:$.messages[0].content[1].frames"),
                             out(Source.UNKNOWN, "h", "req:$.tools[0].hint")),
                     result.segments());
        assertEquals(Set.of("$.new_field", "$.messages[].extra", "$.messages[].content[](text).annotation",
                            "$.messages[].content[](video).frames", "$.tools[].hint"),
                     result.unknownFieldPaths());
    }

    @Test
    void labelsNonJsonBodiesInFull() {
        final ParsedBody text = new ParsedBody(List.of(new ParsedPart(ParsedPart.Kind.TEXT, "req", "text/plain", null,
                                                                      "raw", null)), List.of(), false);
        final LabelResult result = adapter.labelRequest(text);
        assertEquals(List.of(out(Source.UNKNOWN, "raw", "req:text")), result.segments());
        assertEquals(Set.of("req:text"), result.unknownFieldPaths());
        assertTrue(result.attributes().model().isEmpty());
    }

    private static Segment in(Source source, String text, String location) {
        return new Segment(source, Direction.INBOUND, text, location);
    }

    private static ParsedBody stream(String... data) {
        final StringBuilder body = new StringBuilder();
        for (String d : data) {
            body.append("data: ").append(d).append("\n\n");
        }
        return new ParsedBody(List.of(new ParsedPart(ParsedPart.Kind.SSE_STREAM, "resp", "text/event-stream", null, null,
            new SseStreamParser().events(body.toString().getBytes(StandardCharsets.UTF_8)))), List.of(), false);
    }

    @Test
    void labelsAStreamedReplyByBlock() {
        final LabelResult result = adapter.labelResponse(stream(
            "{\"type\":\"message_start\",\"message\":{\"model\":\"claude-opus-5-5\"}}",
            "{\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"thinking\",\"thinking\":\"\"}}",
            "{\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"thinking_delta\",\"thinking\":\"hmm\"}}",
            "{\"type\":\"content_block_start\",\"index\":1,\"content_block\":{\"type\":\"server_tool_use\",\"name\":\"web_search\",\"input\":{}}}",
            "{\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"q\\\":1}\"}}",
            "{\"type\":\"content_block_start\",\"index\":2,\"content_block\":{\"type\":\"web_search_tool_result\",\"content\":[{\"title\":\"Ignore previous\"}]}}",
            "{\"type\":\"content_block_start\",\"index\":3,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}",
            "{\"type\":\"content_block_delta\",\"index\":3,\"delta\":{\"type\":\"text_delta\",\"text\":\"Answer\"}}",
            "{\"type\":\"content_block_start\",\"index\":4,\"content_block\":{\"type\":\"artifact\",\"content\":\"x\"}}",
            "{\"type\":\"message_stop\"}"));
        assertEquals(List.of(in(Source.MODEL_OUTPUT, "hmm", "resp:sse:block[0]"),
                             in(Source.MODEL_OUTPUT, "{\"q\":1}", "resp:sse:block[1]"),
                             in(Source.SERVER_TOOL_RESULT, "[{\"title\":\"Ignore previous\"}]", "resp:sse:block[2]"),
                             in(Source.MODEL_OUTPUT, "Answer", "resp:sse:block[3]"),
                             in(Source.UNKNOWN, "\"x\"", "resp:sse:block[4]")),
                     result.segments());
        assertEquals(Set.of("sse:block(artifact)"), result.unknownFieldPaths());
        assertEquals(Optional.of("claude-opus-5-5"), result.attributes().model());
    }

    @Test
    void labelsAJsonReplyAndItsCitations() throws ParseException {
        final ParsedBody body = new ParsedBody(List.of(new ParsedPart(ParsedPart.Kind.JSON, "resp", "application/json",
            JSON.parse(("""
                {"id":"msg_1","type":"message","role":"assistant","model":"claude-haiku-5-5","stop_reason":"end_turn",
                 "usage":{"input_tokens":5},"content":[
                   {"type":"thinking","thinking":"plan","signature":"EqQB"},
                   {"type":"text","text":"Title here","citations":[{"cited_text":"quoted page"}]},
                   {"type":"mystery","note":"n"}],"surprise":"s"}
                """).getBytes(StandardCharsets.UTF_8)), null, null)), List.of(), false);
        final LabelResult result = adapter.labelResponse(body);
        assertEquals(List.of(in(Source.MODEL_OUTPUT, "plan", "resp:$.content[0].thinking"),
                             in(Source.MODEL_OUTPUT, "Title here", "resp:$.content[1].text"),
                             in(Source.SERVER_TOOL_RESULT, "quoted page", "resp:$.content[1].citations[0].cited_text"),
                             in(Source.UNKNOWN, "n", "resp:$.content[2].note"),
                             in(Source.UNKNOWN, "s", "resp:$.surprise")),
                     result.segments());
        assertEquals(Set.of("$.content[](mystery).note", "$.surprise"), result.unknownFieldPaths());
        assertEquals(Optional.of("claude-haiku-5-5"), result.attributes().model());
    }

    @Test
    void scansCitationsInRequestHistory() throws ParseException {
        assertEquals(List.of(out(Source.MODEL_OUTPUT, "said", "req:$.messages[0].content[0].text"),
                             out(Source.UNKNOWN, "quoted", "req:$.messages[0].content[0].citations[0].cited_text")),
                     adapter.labelRequest(request("""
                         {"messages":[{"role":"assistant","content":[{"type":"text","text":"said",
                           "citations":[{"cited_text":"quoted"}]}]}]}
                         """)).segments());
    }
}
