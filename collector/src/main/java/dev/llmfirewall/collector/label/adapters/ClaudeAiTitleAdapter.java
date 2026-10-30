package dev.llmfirewall.collector.label.adapters;

import com.fasterxml.jackson.databind.JsonNode;
import dev.llmfirewall.collector.label.Direction;
import dev.llmfirewall.collector.label.EndpointRouter;
import dev.llmfirewall.collector.label.LabelResult;
import dev.llmfirewall.collector.label.Segment;
import dev.llmfirewall.collector.label.Source;
import dev.llmfirewall.collector.parse.ParsedBody;
import dev.llmfirewall.collector.parse.ParsedPart;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;

/**
 * claude.ai's title endpoints (mapping v1, from the 2026-10-30 schema survey):
 * <pre>
 *  title           request  message_content         USER_TYPED   (a copy of the typed message)
 *                  request  recent_titles           UNKNOWN
 *                  reply    title                   MODEL_OUTPUT
 *  generate_title  request  first_session_message   USER_TYPED
 *                  request  model, title_style      metadata
 *                  reply    title, branch_name      MODEL_OUTPUT
 * </pre>
 * Every other field, and any part that is not a JSON object, is labeled UNKNOWN in full
 * and its path reported as unknown. Stateless and thread-safe.
 */
public final class ClaudeAiTitleAdapter {

    public static final String ID = "claude-ai.title";
    public static final int VERSION = 1;

    /** Field to source, by endpoint name; a null source marks metadata. */
    private static final Map<String, Map<String, Source>> REQUEST = Map.of(
        "title", Map.of("message_content", Source.USER_TYPED, "recent_titles", Source.UNKNOWN),
        "generate_title", fieldsWithMetadata(Map.of("first_session_message", Source.USER_TYPED), "model", "title_style"));
    private static final Map<String, Map<String, Source>> REPLY = Map.of(
        "title", Map.of("title", Source.MODEL_OUTPUT),
        "generate_title", Map.of("title", Source.MODEL_OUTPUT, "branch_name", Source.MODEL_OUTPUT));

    /** Whether {@code endpoint} (an endpoint name) is one this adapter labels. */
    public static boolean supports(String endpoint) {
        return REQUEST.containsKey(endpoint);
    }

    public LabelResult labelRequest(String endpoint, ParsedBody body) {
        return label(REQUEST.getOrDefault(endpoint, Map.of()), body, Direction.OUTBOUND);
    }

    public LabelResult labelResponse(String endpoint, ParsedBody body) {
        return label(REPLY.getOrDefault(endpoint, Map.of()), body, Direction.INBOUND);
    }

    private static LabelResult label(Map<String, Source> schema, ParsedBody body, Direction direction) {
        final List<Segment> segments = new ArrayList<>();
        final TreeSet<String> unknown = new TreeSet<>();
        Optional<String> model = Optional.empty();
        for (ParsedPart part : body.parts()) {
            if (part.kind() != ParsedPart.Kind.JSON || !part.json().isObject()) {
                segments.addAll(new FallbackAdapter().segments(new ParsedBody(List.of(part), List.of(), false), direction));
                unknown.add(part.location() + ":" + part.kind().name().toLowerCase());
                continue;
            }
            for (Map.Entry<String, JsonNode> field : part.json().properties()) {
                final String key = field.getKey();
                final String path = part.location() + ":$" + FallbackAdapter.keyPath(key);
                if (schema.containsKey(key) && schema.get(key) == null) {
                    if (key.equals("model") && field.getValue().isTextual()) {
                        model = Optional.of(field.getValue().textValue());
                    }
                    continue;
                }
                final Source source = schema.getOrDefault(key, Source.UNKNOWN);
                final List<Segment> found = new ArrayList<>();
                FallbackAdapter.json(field.getValue(), path, direction, found);
                found.forEach(s -> segments.add(new Segment(source, direction, s.text(), s.location())));
                if (!schema.containsKey(key)) {
                    unknown.add("$" + (EndpointRouter.isIdLike(key) ? "[*]" : FallbackAdapter.keyPath(key)));
                }
            }
        }
        return new LabelResult(List.copyOf(segments), Set.copyOf(unknown), new LabelResult.Attributes(model, false));
    }

    private static Map<String, Source> fieldsWithMetadata(Map<String, Source> fields, String... metadata) {
        final Map<String, Source> out = new HashMap<>(fields);
        for (String key : metadata) {
            out.put(key, null);
        }
        return out;
    }
}
