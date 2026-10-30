package dev.llmfirewall.collector.label;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.llmfirewall.collector.label.adapters.AnthropicMessagesAdapter;
import dev.llmfirewall.collector.parse.JsonBodyParser;
import dev.llmfirewall.collector.parse.ParseException;
import dev.llmfirewall.collector.parse.ParsedBody;
import dev.llmfirewall.collector.parse.ParsedPart;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.Test;

class AnthropicMessagesAdapterTest {

    private final AnthropicMessagesAdapter adapter = new AnthropicMessagesAdapter();

    private static ParsedBody request(String json) throws ParseException {
        return new ParsedBody(List.of(new ParsedPart(ParsedPart.Kind.JSON, "req", "application/json",
            new JsonBodyParser(100, 1 << 20).parse(json.getBytes(StandardCharsets.UTF_8)), null, null)), List.of(), false);
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
