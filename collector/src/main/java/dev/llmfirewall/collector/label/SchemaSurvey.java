package dev.llmfirewall.collector.label;

import com.fasterxml.jackson.databind.JsonNode;
import dev.llmfirewall.collector.coverage.CoverageCounters;
import dev.llmfirewall.collector.coverage.CoverageMetric;
import dev.llmfirewall.collector.label.adapters.FallbackAdapter;
import dev.llmfirewall.collector.parse.JsonBodyParser;
import dev.llmfirewall.collector.parse.ParseException;
import dev.llmfirewall.collector.parse.ParsedBody;
import dev.llmfirewall.collector.parse.ParsedPart;
import dev.llmfirewall.collector.parse.SseStreamParser;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.TreeSet;
import java.util.regex.Pattern;

/**
 * Records the shape of a routed endpoint's bodies, never their values: each distinct
 * JSON key path with its value type is counted once per body as
 * SCHEMA_SURVEY[{@code <endpoint> <part>:<path>:<type>}], for example
 * {@code completion req:$.prompt:string}. Array indices collapse to {@code []}, and keys
 * that are not plain identifiers become {@code [*]}, as in {@link FallbackAdapter}.
 * Types are {@code string}, {@code number}, {@code boolean}, {@code null},
 * {@code object} (empty) and {@code array} (empty).
 *
 * <p>An SSE body is surveyed per event: each event's data is parsed as JSON and its
 * paths are prefixed with {@code sse:<type>}, the value of its {@code type} field (or
 * {@code [*]} if that is missing or not a plain identifier). Event data that is not JSON
 * counts as {@code sse:<event>:text}. TEXT parts count as {@code text}; skipped parts
 * are not surveyed. Thread-safe.
 */
public final class SchemaSurvey {

    private static final Pattern PLAIN = Pattern.compile("[A-Za-z0-9_-]{1,64}");

    private final JsonBodyParser json;
    private final CoverageCounters coverage;

    public SchemaSurvey(JsonBodyParser json, CoverageCounters coverage) {
        this.json = json;
        this.coverage = coverage;
    }

    /** Surveys one body of a known endpoint; unknown endpoints are ignored. */
    public void survey(EndpointKey endpoint, ParsedBody body) {
        if (!endpoint.known()) {
            return;
        }
        final TreeSet<String> shapes = new TreeSet<>();
        for (ParsedPart part : body.parts()) {
            switch (part.kind()) {
                case JSON -> shape(part.json(), part.location() + ":$", shapes);
                case TEXT -> shapes.add(part.location() + ":text");
                case SSE_STREAM -> {
                    for (SseStreamParser.SseEvent event : part.sseEvents()) {
                        sseEvent(part.location(), event, shapes);
                    }
                }
                case BINARY_SKIPPED -> {
                    // Nothing was read from it.
                }
            }
        }
        for (String shape : shapes) {
            coverage.increment(CoverageMetric.SCHEMA_SURVEY, endpoint.name() + " " + shape);
        }
    }

    private void sseEvent(String location, SseStreamParser.SseEvent event, TreeSet<String> shapes) {
        try {
            final JsonNode data = json.parse(event.data().getBytes(StandardCharsets.UTF_8));
            final String type = data.path("type").asText("");
            shape(data, location + ":sse:" + (PLAIN.matcher(type).matches() ? type : "[*]") + ":$", shapes);
        } catch (ParseException e) {
            shapes.add(location + ":sse:" + (PLAIN.matcher(event.event()).matches() ? event.event() : "[*]") + ":text");
        }
    }

    private static void shape(JsonNode node, String path, TreeSet<String> shapes) {
        if (node.isObject() && !node.isEmpty()) {
            for (Map.Entry<String, JsonNode> field : node.properties()) {
                shape(field.getValue(), path + FallbackAdapter.keyPath(field.getKey()), shapes);
            }
        } else if (node.isArray() && !node.isEmpty()) {
            for (JsonNode element : node) {
                shape(element, path + "[]", shapes);
            }
        } else {
            shapes.add(path + ":" + type(node));
        }
    }

    private static String type(JsonNode node) {
        return switch (node.getNodeType()) {
            case STRING -> "string";
            case NUMBER -> "number";
            case BOOLEAN -> "boolean";
            case NULL -> "null";
            case OBJECT -> "object";
            case ARRAY -> "array";
            default -> "other";
        };
    }
}
