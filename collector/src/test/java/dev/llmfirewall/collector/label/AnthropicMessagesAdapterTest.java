package dev.llmfirewall.collector.label;

import static org.junit.jupiter.api.Assertions.assertEquals;
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
    void labelsSystemAndConversationText() throws ParseException {
        final LabelResult result = adapter.labelRequest(request("""
            {"model":"claude-opus-5-5","max_tokens":32000,"stream":true,"metadata":{"user_id":"u1"},
             "thinking":{"type":"adaptive"},
             "system":[{"type":"text","text":"You are Claude Code.","cache_control":{"type":"ephemeral"}}],
             "messages":[
               {"role":"user","content":"fix the bug"},
               {"role":"assistant","content":[{"type":"text","text":"Reading it."}]},
               {"role":"assistant","content":"Done."},
               {"role":"user","content":[{"type":"text","text":"<system-reminder>be careful</system-reminder>",
                                          "cache_control":{"type":"ephemeral"}}]}]}
            """));
        assertEquals(List.of(
            out(Source.UNKNOWN, "You are Claude Code.", "req:$.system[0].text"),
            out(Source.UNKNOWN, "fix the bug", "req:$.messages[0].content"),
            out(Source.MODEL_OUTPUT, "Reading it.", "req:$.messages[1].content[0].text"),
            out(Source.MODEL_OUTPUT, "Done.", "req:$.messages[2].content"),
            out(Source.UNKNOWN, "<system-reminder>be careful</system-reminder>", "req:$.messages[3].content[0].text")),
            result.segments());
        assertEquals(Set.of(), result.unknownFieldPaths());
        assertEquals(new LabelResult.Attributes(Optional.of("claude-opus-5-5"), false), result.attributes());
    }

    @Test
    void acceptsAPlainStringSystemPrompt() throws ParseException {
        assertEquals(List.of(out(Source.UNKNOWN, "Be brief.", "req:$.system")),
                     adapter.labelRequest(request("{\"system\":\"Be brief.\"}")).segments());
    }

    @Test
    void labelsAndReportsFieldsOutsideTheSchema() throws ParseException {
        final LabelResult result = adapter.labelRequest(request("""
            {"model":"m","new_field":{"note":"hidden"},"messages":[{"role":"user","extra":"x",
              "content":[{"type":"text","text":"hi","annotation":"y"},{"type":"video","frames":"z"}]}],
             "tools":[{"name":"T","description":"d"}]}
            """));
        assertEquals(List.of(out(Source.UNKNOWN, "hidden", "req:$.new_field.note"),
                             out(Source.UNKNOWN, "x", "req:$.messages[0].extra"),
                             out(Source.UNKNOWN, "hi", "req:$.messages[0].content[0].text"),
                             out(Source.UNKNOWN, "y", "req:$.messages[0].content[0].annotation"),
                             out(Source.UNKNOWN, "z", "req:$.messages[0].content[1].frames"),
                             out(Source.UNKNOWN, "T", "req:$.tools[0].name"),
                             out(Source.UNKNOWN, "d", "req:$.tools[0].description")),
                     result.segments());
        assertEquals(Set.of("$.new_field", "$.messages[].extra", "$.messages[].content[](text).annotation",
                            "$.messages[].content[](video).frames", "$.tools"),
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
}
