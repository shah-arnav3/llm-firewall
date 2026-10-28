package dev.llmfirewall.collector.parse;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class JsonBodyParserTest {

    private final JsonBodyParser parser = new JsonBodyParser(20, 100);

    private JsonNode parse(String json) throws ParseException {
        return parser.parse(json.getBytes(StandardCharsets.UTF_8));
    }

    private String code(String json) {
        return assertThrows(ParseException.class, () -> parse(json)).code();
    }

    @Test
    void parsesAMessagesRequest() throws ParseException {
        final JsonNode tree = parse("{\"model\":\"claude\",\"messages\":[{\"role\":\"user\",\"content\":\"hi\"}]}");
        assertEquals("claude", tree.get("model").asText());
        assertEquals("hi", tree.at("/messages/0/content").asText());
    }

    @Test
    void acceptsAnyTopLevelValueAndSurroundingWhitespace() throws ParseException {
        assertTrue(parse(" [1, 2] \n").isArray());
        assertEquals("x", parse("\"x\"").asText());
    }

    @Test
    void rejectsSyntaxErrorsTrailingContentAndTruncation() {
        assertEquals("json:syntax", code("{\"a\":"));
        assertEquals("json:syntax", code("{\"a\":1} {\"b\":2}"));
        assertEquals("json:syntax", code("{\"a\":1}x"));
        assertEquals("json:syntax", code("not json"));
    }

    @Test
    void rejectsAnEmptyBody() {
        assertEquals("json:empty", code(""));
        assertEquals("json:empty", code("  \n"));
    }

    @Test
    void enforcesTheNestingLimit() throws ParseException {
        assertTrue(parse("[".repeat(20) + "]".repeat(20)).isArray());
        assertEquals("json:limit", code("[".repeat(21) + "]".repeat(21)));
    }

    @Test
    void enforcesTheStringLimit() throws ParseException {
        assertEquals(100, parse("\"" + "s".repeat(100) + "\"").asText().length());
        assertEquals("json:limit", code("\"" + "s".repeat(101) + "\""));
        assertEquals("json:limit", code("{\"" + "k".repeat(101) + "\":1}"), "keys count too");
    }

    @Test
    void rejectsNonPositiveLimits() {
        assertThrows(IllegalArgumentException.class, () -> new JsonBodyParser(0, 100));
        assertThrows(IllegalArgumentException.class, () -> new JsonBodyParser(20, 0));
    }

    @Test
    void recognisesJsonContentTypes() {
        for (String type : new String[] {"application/json", "Application/JSON; charset=utf-8", "application/problem+json",
                                         " application/vnd.api+json "}) {
            assertTrue(JsonBodyParser.supports(type), type);
        }
        for (String type : new String[] {null, "", "text/event-stream", "text/json+html", "+json", "application/jsonp"}) {
            assertFalse(JsonBodyParser.supports(type), String.valueOf(type));
        }
    }
}
