package dev.llmfirewall.collector.label;

import static org.junit.jupiter.api.Assertions.assertEquals;

import dev.llmfirewall.collector.coverage.CoverageCounters;
import dev.llmfirewall.collector.coverage.CoverageMetric;
import dev.llmfirewall.collector.parse.JsonBodyParser;
import dev.llmfirewall.collector.parse.ParseException;
import dev.llmfirewall.collector.parse.ParsedBody;
import dev.llmfirewall.collector.parse.ParsedPart;
import dev.llmfirewall.collector.parse.SseStreamParser;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import org.junit.jupiter.api.Test;

class SchemaSurveyTest {

    private static final JsonBodyParser JSON = new JsonBodyParser(50, 1 << 20);
    private static final EndpointKey COMPLETION = new EndpointKey("completion", "claude.ai", "POST", "/t", Map.of(), true);

    private final CoverageCounters coverage = new CoverageCounters(100, Clock.systemDefaultZone());
    private final SchemaSurvey survey = new SchemaSurvey(JSON, coverage);

    private static ParsedBody jsonBody(String location, String text) throws ParseException {
        return new ParsedBody(List.of(new ParsedPart(ParsedPart.Kind.JSON, location, "application/json",
                                                     JSON.parse(text.getBytes(StandardCharsets.UTF_8)), null, null)),
                              List.of(), false);
    }

    private Map<String, Long> surveyed() {
        final Map<String, Long> out = new TreeMap<>();
        coverage.drain().stream().filter(d -> d.metric() == CoverageMetric.SCHEMA_SURVEY)
            .forEach(d -> out.put(d.dimension(), d.delta()));
        return out;
    }

    @Test
    void recordsPathsAndTypesWithoutValues() throws ParseException {
        survey.survey(COMPLETION, jsonBody("req",
            "{\"prompt\":\"secret words\",\"attachments\":[{\"size\":3},{\"size\":4,\"name\":\"a.pdf\"}],"
            + "\"tools\":[],\"meta\":{},\"flag\":true,\"x\":null,\"alice@example.com\":1}"));
        assertEquals(Map.of("completion req:$.prompt:string", 1L,
                            "completion req:$.attachments[].size:number", 1L,
                            "completion req:$.attachments[].name:string", 1L,
                            "completion req:$.tools:array", 1L,
                            "completion req:$.meta:object", 1L,
                            "completion req:$.flag:boolean", 1L,
                            "completion req:$.x:null", 1L,
                            "completion req:$[*]:number", 1L),
                     surveyed());
    }

    @Test
    void collapsesIdLikeKeys() throws ParseException {
        survey.survey(COMPLETION, jsonBody("resp", "{\"tool_uses\":{\"toolu_011GBiWwA1jve497uAWKe9KL\":{\"outcome\":\"ok\"},"
            + "\"toolu_01LEBm4Mkgp5B77D7oDyjCv5\":{\"outcome\":\"ok\"}},\"windows\":{\"5h\":1}}"));
        assertEquals(Map.of("completion resp:$.tool_uses[*].outcome:string", 1L, "completion resp:$.windows.5h:number", 1L),
                     surveyed());
    }

    @Test
    void countsEachShapeOncePerBody() throws ParseException {
        survey.survey(COMPLETION, jsonBody("req", "{\"a\":[\"x\",\"y\",\"z\"]}"));
        survey.survey(COMPLETION, jsonBody("req", "{\"a\":[\"x\"]}"));
        assertEquals(Map.of("completion req:$.a[]:string", 2L), surveyed());
    }

    @Test
    void surveysSseEventsByTheirType() {
        final String stream = "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"model\":\"m\"}}\n\n"
            + "data: {\"type\":\"content_block_delta\",\"delta\":{\"text\":\"secret\"}}\n\n"
            + "data: {\"type\":\"content_block_delta\",\"delta\":{\"text\":\"more\"}}\n\n"
            + "event: done\ndata: [DONE\n\n";
        final ParsedPart part = new ParsedPart(ParsedPart.Kind.SSE_STREAM, "resp", "text/event-stream", null, null,
                                               new SseStreamParser().events(stream.getBytes(StandardCharsets.UTF_8)));
        survey.survey(COMPLETION, new ParsedBody(List.of(part), List.of(), false));
        assertEquals(Map.of("completion resp:sse:message_start:$.type:string", 1L,
                            "completion resp:sse:message_start:$.message.model:string", 1L,
                            "completion resp:sse:content_block_delta:$.type:string", 1L,
                            "completion resp:sse:content_block_delta:$.delta.text:string", 1L,
                            "completion resp:sse:done:text", 1L),
                     surveyed());
    }

    @Test
    void ignoresUnknownEndpoints() throws ParseException {
        survey.survey(new EndpointKey("", "claude.ai", "POST", "/x", Map.of(), false), jsonBody("req", "{\"a\":1}"));
        assertEquals(Map.of(), surveyed());
    }
}
