package dev.llmfirewall.collector.label;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.llmfirewall.collector.label.adapters.ClaudeAiTitleAdapter;
import dev.llmfirewall.collector.parse.JsonBodyParser;
import dev.llmfirewall.collector.parse.ParseException;
import dev.llmfirewall.collector.parse.ParsedBody;
import dev.llmfirewall.collector.parse.ParsedPart;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.Test;

class ClaudeAiTitleAdapterTest {

    private final ClaudeAiTitleAdapter adapter = new ClaudeAiTitleAdapter();

    private static ParsedBody json(String location, String text) throws ParseException {
        return new ParsedBody(List.of(new ParsedPart(ParsedPart.Kind.JSON, location, "application/json",
            new JsonBodyParser(50, 1 << 20).parse(text.getBytes(StandardCharsets.UTF_8)), null, null)), List.of(), false);
    }

    @Test
    void labelsTitleRequestsAndReplies() throws ParseException {
        final LabelResult request = adapter.labelRequest("title",
            json("req", "{\"message_content\":\"plan my trip\",\"recent_titles\":[\"Old chat\"]}"));
        assertEquals(List.of(new Segment(Source.USER_TYPED, Direction.OUTBOUND, "plan my trip", "req:$.message_content"),
                             new Segment(Source.UNKNOWN, Direction.OUTBOUND, "Old chat", "req:$.recent_titles[0]")),
                     request.segments());
        assertEquals(Set.of(), request.unknownFieldPaths());
        assertEquals(List.of(new Segment(Source.MODEL_OUTPUT, Direction.INBOUND, "Trip planning", "resp:$.title")),
                     adapter.labelResponse("title", json("resp", "{\"title\":\"Trip planning\"}")).segments());
    }

    @Test
    void labelsGenerateTitleRequestsAndReplies() throws ParseException {
        final LabelResult request = adapter.labelRequest("generate_title",
            json("req", "{\"first_session_message\":\"add a cache\",\"model\":\"claude-haiku-5-5\",\"title_style\":\"short\"}"));
        assertEquals(List.of(new Segment(Source.USER_TYPED, Direction.OUTBOUND, "add a cache", "req:$.first_session_message")),
                     request.segments());
        assertEquals(Optional.of("claude-haiku-5-5"), request.attributes().model());
        final LabelResult reply = adapter.labelResponse("generate_title",
            json("resp", "{\"title\":\"Add caching\",\"branch_name\":\"add-cache\"}"));
        assertEquals(List.of("resp:$.title", "resp:$.branch_name"), reply.segments().stream().map(Segment::location).toList());
        assertTrue(reply.segments().stream().allMatch(s -> s.source() == Source.MODEL_OUTPUT));
    }

    @Test
    void labelsAndReportsFieldsOutsideTheSchema() throws ParseException {
        final LabelResult result = adapter.labelRequest("title", json("req", "{\"message_content\":\"a\",\"draft\":{\"text\":\"b\"}}"));
        assertEquals(new Segment(Source.UNKNOWN, Direction.OUTBOUND, "b", "req:$.draft.text"), result.segments().get(1));
        assertEquals(Set.of("$.draft"), result.unknownFieldPaths());
    }

    @Test
    void supportsOnlyTheTitleEndpoints() {
        assertTrue(ClaudeAiTitleAdapter.supports("title"));
        assertTrue(ClaudeAiTitleAdapter.supports("generate_title"));
        assertFalse(ClaudeAiTitleAdapter.supports("completion"));
    }
}
