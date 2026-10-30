package dev.llmfirewall.collector.parse;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.llmfirewall.collector.parse.SseReplyAssembler.AssembledReply;
import dev.llmfirewall.collector.parse.SseReplyAssembler.Block;
import java.nio.charset.StandardCharsets;
import java.util.List;
import org.junit.jupiter.api.Test;

class SseReplyAssemblerTest {

    private final SseReplyAssembler assembler = new SseReplyAssembler(new JsonBodyParser(100, 1 << 20));

    private AssembledReply assemble(String... dataLines) {
        final StringBuilder body = new StringBuilder();
        for (String data : dataLines) {
            body.append("data: ").append(data).append("\n\n");
        }
        return assembler.assemble(new SseStreamParser().events(body.toString().getBytes(StandardCharsets.UTF_8)));
    }

    private static final String START = "{\"type\":\"message_start\",\"message\":{\"model\":\"claude-opus-5-5\",\"content\":[]}}";
    private static final String STOP = "{\"type\":\"message_stop\"}";

    @Test
    void assemblesTextDeltasIntoBlocks() {
        final AssembledReply reply = assemble(
            START,
            "{\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}",
            "{\"type\":\"ping\"}",
            "{\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Hello\"}}",
            "{\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\", world\"}}",
            "{\"type\":\"content_block_stop\",\"index\":0}",
            "{\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"}}",
            STOP);
        assertEquals(new AssembledReply("claude-opus-5-5", "end_turn", List.of(new Block(0, "text", "Hello, world", "", true)), true),
                     reply);
    }

    @Test
    void keepsThinkingAndToolInputAndDropsSignatures() {
        final AssembledReply reply = assemble(
            START,
            "{\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"thinking\",\"thinking\":\"\"}}",
            "{\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"thinking_delta\",\"thinking\":\"Let me check.\"}}",
            "{\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"signature_delta\",\"signature\":\"EqQB\"}}",
            "{\"type\":\"content_block_stop\",\"index\":0}",
            "{\"type\":\"content_block_start\",\"index\":1,\"content_block\":{\"type\":\"tool_use\",\"id\":\"t1\",\"name\":\"read_file\",\"input\":{}}}",
            "{\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"path\\\":\"}}",
            "{\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"\\\"a.txt\\\"}\"}}",
            "{\"type\":\"content_block_stop\",\"index\":1}",
            STOP);
        assertEquals(List.of(new Block(0, "thinking", "Let me check.", "", true),
                             new Block(1, "tool_use", "{\"path\":\"a.txt\"}", "read_file", true)),
                     reply.blocks());
    }

    @Test
    void keepsServerToolResultBlocksSeparate() {
        final AssembledReply reply = assemble(
            START,
            "{\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"server_tool_use\",\"id\":\"s1\",\"name\":\"web_search\",\"input\":{}}}",
            "{\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"query\\\":\\\"x\\\"}\"}}",
            "{\"type\":\"content_block_stop\",\"index\":0}",
            "{\"type\":\"content_block_start\",\"index\":1,\"content_block\":{\"type\":\"web_search_tool_result\",\"tool_use_id\":\"s1\",\"content\":[{\"title\":\"Page\",\"url\":\"https://example.com\"}]}}",
            "{\"type\":\"content_block_stop\",\"index\":1}",
            STOP);
        assertEquals(List.of(new Block(0, "server_tool_use", "{\"query\":\"x\"}", "web_search", true),
                             new Block(1, "unknown:web_search_tool_result",
                                       "[{\"title\":\"Page\",\"url\":\"https://example.com\"}]", "", true)),
                     reply.blocks());
    }

    @Test
    void preservesUnknownBlockAndDeltaTypes() {
        final AssembledReply reply = assemble(
            START,
            "{\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"artifact\"}}",
            "{\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"artifact_delta\",\"body\":\"secret\"}}",
            "{\"type\":\"content_block_delta\",\"index\":3,\"delta\":{\"type\":\"text_delta\",\"text\":\"orphan\"}}",
            STOP);
        assertEquals(List.of(new Block(0, "unknown:artifact", "{\"type\":\"artifact_delta\",\"body\":\"secret\"}", "", false),
                             new Block(3, "unknown:missing_start", "orphan", "", false)),
                     reply.blocks());
    }

    @Test
    void extractsModelFromMessageStart() {
        assertEquals("claude-opus-5-5", assemble(START).model());
        assertEquals("", assemble(STOP).model());
    }

    @Test
    void aTruncatedStreamKeepsWhatArrivedAndIsIncomplete() {
        final String body = "data: " + START + "\n\n"
            + "data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n"
            + "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Hel\"}}\n\n"
            + "data: {\"type\":\"content_block_delta\",\"index\":0,\"del";
        final AssembledReply reply = assembler.assemble(new SseStreamParser().events(body.getBytes(StandardCharsets.UTF_8)));
        assertEquals(List.of(new Block(0, "text", "Hel", "", false)), reply.blocks());
        assertFalse(reply.complete());
    }

    @Test
    void anUnparsableEventMakesTheReplyIncomplete() {
        final AssembledReply reply = assemble(START, "not json", STOP);
        assertFalse(reply.complete());
        assertTrue(assemble(START, STOP).complete());
    }

    @Test
    void keepsCitationsApartFromTheText() {
        final AssembledReply reply = assemble(
            START,
            "{\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\",\"citations\":[{\"cited_text\":\"a\"}]}}",
            "{\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Per the page\"}}",
            "{\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"citations_delta\",\"citation\":{\"cited_text\":\"b\"}}}",
            "{\"type\":\"content_block_stop\",\"index\":0}",
            STOP);
        assertEquals(List.of(new Block(0, "text", "Per the page", "", true, "[{\"cited_text\":\"a\"},{\"cited_text\":\"b\"}]")),
                     reply.blocks());
        assertEquals("", assemble(START, "{\"type\":\"content_block_start\",\"index\":0,\"content_block\":"
                                         + "{\"type\":\"text\",\"text\":\"x\",\"citations\":[]}}").blocks().get(0).citations());
    }
}
