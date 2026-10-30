package dev.llmfirewall.collector.label;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.llmfirewall.collector.coverage.CoverageCounters;
import dev.llmfirewall.collector.coverage.CoverageMetric;
import dev.llmfirewall.collector.label.adapters.AnthropicMessagesAdapter;
import dev.llmfirewall.collector.parse.JsonBodyParser;
import dev.llmfirewall.collector.parse.ParseException;
import dev.llmfirewall.collector.parse.ParsedBody;
import dev.llmfirewall.collector.parse.ParsedPart;
import dev.llmfirewall.collector.parse.SseReplyAssembler;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;
import org.junit.jupiter.api.Test;

class LabelerTest {

    private static final JsonBodyParser JSON = new JsonBodyParser(100, 1 << 20);
    private static final String ORG = "02812373-138d-4a58-874b-33e46fa50871";
    private static final String CONV = "f85e431c-3b8b-4dc7-aaa0-6ec211804df8";

    private final CoverageCounters coverage = new CoverageCounters(100, Clock.systemDefaultZone());
    private final Labeler labeler = new Labeler(new AnthropicMessagesAdapter(new SseReplyAssembler(JSON)), coverage);
    private final EndpointRouter router = new EndpointRouter();

    private static ParsedBody json(String location, String text) throws ParseException {
        return new ParsedBody(List.of(new ParsedPart(ParsedPart.Kind.JSON, location, "application/json",
            JSON.parse(text.getBytes(StandardCharsets.UTF_8)), null, null)), List.of(), false);
    }

    private Map<String, Long> counted() {
        final Map<String, Long> out = new TreeMap<>();
        coverage.drain().forEach(d -> out.put(d.metric() + "[" + d.dimension() + "]", d.delta()));
        return out;
    }

    @Test
    void labelsAMessagesExchangeAndCountsDrift() throws ParseException {
        final LabeledExchange labeled = labeler.label(router.route("api.anthropic.com", "POST", "/v1/messages"),
            json("req", "{\"model\":\"claude-opus-5-5\",\"messages\":[{\"role\":\"user\",\"content\":\"hi\"}],\"new_field\":\"x\"}"),
            json("resp", "{\"content\":[{\"type\":\"text\",\"text\":\"hello\"}],\"surprise\":\"s\"}"));
        assertEquals("anthropic.messages@1", labeled.adapterId());
        assertEquals(List.of("hi", "x", "hello", "s"), labeled.result().segments().stream().map(Segment::text).toList());
        assertEquals(Optional.of("claude-opus-5-5"), labeled.result().attributes().model());
        assertEquals(Map.of("SCHEMA_DRIFT[anthropic.messages@1 req:$.new_field]", 1L,
                            "SCHEMA_DRIFT[anthropic.messages@1 resp:$.surprise]", 1L),
                     counted());
    }

    @Test
    void routesClaudeAiEndpointsToTheirAdapters() throws ParseException {
        final String base = "/api/organizations/" + ORG + "/chat_conversations/" + CONV;
        assertEquals("claude-ai.completion@1",
                     labeler.label(router.route("claude.ai", "POST", base + "/completion"), json("req", "{\"prompt\":\"p\"}"),
                                   ParsedBody.EMPTY).adapterId());
        final LabeledExchange title = labeler.label(router.route("claude.ai", "POST", base + "/title"),
                                                    json("req", "{\"message_content\":\"m\"}"), ParsedBody.EMPTY);
        assertEquals("claude-ai.title@1", title.adapterId());
        assertEquals(Source.USER_TYPED, title.result().segments().get(0).source());
        assertEquals(Map.of(), counted());
    }

    @Test
    void anUnroutedEndpointIsLabeledInFullAndCounted() throws ParseException {
        final LabeledExchange labeled = labeler.label(router.route("claude.ai", "GET", "/api/organizations/" + ORG + "/usage"),
                                                      ParsedBody.EMPTY, json("resp", "{\"plan\":\"pro\"}"));
        assertEquals(Labeler.FALLBACK_ID, labeled.adapterId());
        assertEquals(List.of(new Segment(Source.UNKNOWN, Direction.INBOUND, "pro", "resp:$.plan")), labeled.result().segments());
        assertEquals(Map.of("UNKNOWN_ENDPOINT[claude.ai GET /api/organizations/{id}/usage]", 1L), counted());
        labeler.label(router.route("claude.ai", "GET", "/api/x"), ParsedBody.EMPTY, ParsedBody.EMPTY);
        assertEquals(Map.of(), counted(), "an exchange without text is not counted");
    }

    @Test
    void aThrowingAdapterFallsBackAndIsCounted() throws ParseException {
        // A messages body whose "messages" is an object makes the adapter fail on get(i).
        final LabeledExchange labeled = labeler.label(router.route("api.anthropic.com", "POST", "/v1/messages"),
            json("req", "{\"messages\":{\"oops\":\"text\"}}"), ParsedBody.EMPTY);
        assertEquals(Labeler.FALLBACK_ID, labeled.adapterId());
        assertEquals(List.of(new Segment(Source.UNKNOWN, Direction.OUTBOUND, "text", "req:$.messages.oops")),
                     labeled.result().segments());
        assertTrue(counted().containsKey("ADAPTER_FAILURE[anthropic.messages@1]"));
    }
}
