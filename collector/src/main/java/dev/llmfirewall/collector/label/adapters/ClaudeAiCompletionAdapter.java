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
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;

/**
 * claude.ai {@code .../chat_conversations/{conv}/completion}, the app's chat endpoint
 * (mapping v1, from the 2026-10-30 schema survey). Requests:
 * <ul>
 *   <li>{@code prompt}: USER_TYPED, the text typed into the prompt box.</li>
 *   <li>every string in {@code attachments}: ATTACHMENT.</li>
 *   <li>{@code tools[].description}, every string in {@code tools[].input_schema}, every
 *       string in {@code sync_sources}, and {@code create_conversation_params.name}:
 *       UNKNOWN. Tool definitions come from MCP servers and connectors.</li>
 * </ul>
 * Known metadata (model and settings, file ids, message ids, tool flags and server ids)
 * gives no segment. Every other field is labeled UNKNOWN in full and its path reported as
 * unknown, and so is a value of the wrong JSON type where an array or object is expected,
 * as {@code path(type)}. Replies use the Messages streaming grammar, plus {@code conversation_ready}
 * and {@code message_limit} events that carry no content, so they are labeled by
 * {@link AnthropicMessagesAdapter#labelResponse}. Thread-safe.
 */
public final class ClaudeAiCompletionAdapter {

    public static final String ID = "claude-ai.completion";
    public static final int VERSION = 1;

    private static final Set<String> METADATA = Set.of("model", "completion_request_id", "effort", "files", "locale",
        "rendering_mode", "thinking_mode", "timezone", "turn_message_uuids");
    private static final Set<String> TOOL_METADATA = Set.of("name", "type", "backend_execution", "integration_name",
        "is_mcp_app", "mcp_server_url", "mcp_server_uuid", "needs_approval", "read_only_hint");
    private static final Set<String> CONVERSATION_METADATA = Set.of("chat_memory_mode", "compass_mode", "enabled_imagine",
        "include_conversation_preferences", "is_temporary", "model", "paprika_mode", "tool_search_mode");

    private final AnthropicMessagesAdapter replies;

    public ClaudeAiCompletionAdapter(AnthropicMessagesAdapter replies) {
        this.replies = replies;
    }

    public LabelResult labelResponse(ParsedBody body) {
        return replies.labelResponse(body);
    }

    /** Labels a request body. Non-JSON parts are labeled by {@link FallbackAdapter} and reported as unknown. */
    public LabelResult labelRequest(ParsedBody body) {
        final List<Segment> segments = new ArrayList<>();
        final TreeSet<String> unknown = new TreeSet<>();
        Optional<String> model = Optional.empty();
        for (ParsedPart part : body.parts()) {
            if (part.kind() != ParsedPart.Kind.JSON || !part.json().isObject()) {
                segments.addAll(new FallbackAdapter().segments(new ParsedBody(List.of(part), List.of(), false),
                                                               Direction.OUTBOUND));
                unknown.add(part.location() + ":" + part.kind().name().toLowerCase());
                continue;
            }
            final String at = part.location() + ":$";
            for (Map.Entry<String, JsonNode> field : part.json().properties()) {
                final String key = field.getKey();
                final JsonNode value = field.getValue();
                final String path = at + FallbackAdapter.keyPath(key);
                switch (key) {
                    case "prompt" -> label(value, path, Source.USER_TYPED, segments);
                    case "attachments" -> label(value, path, Source.ATTACHMENT, segments);
                    case "sync_sources" -> label(value, path, Source.UNKNOWN, segments);
                    case "tools" -> tools(value, path, segments, unknown);
                    case "create_conversation_params" ->
                        fields(value, path, "$.create_conversation_params", CONVERSATION_METADATA, segments, unknown);
                    default -> {
                        if (key.equals("model") && value.isTextual()) {
                            model = Optional.of(value.textValue());
                        } else if (!METADATA.contains(key)) {
                            label(value, path, Source.UNKNOWN, segments);
                            unknown.add("$" + schemaKey(key));
                        }
                    }
                }
            }
        }
        return new LabelResult(List.copyOf(segments), Set.copyOf(unknown), new LabelResult.Attributes(model, false));
    }

    private static void tools(JsonNode tools, String path, List<Segment> segments, TreeSet<String> unknown) {
        if (!tools.isArray()) {
            wrongType(tools, path, "$.tools", segments, unknown);
            return;
        }
        for (int i = 0; i < tools.size(); i++) {
            fields(tools.get(i), path + "[" + i + "]", "$.tools[]", TOOL_METADATA, segments, unknown);
        }
    }

    /**
     * An object whose {@code metadata} keys give no segment; every other key is labeled
     * UNKNOWN, and is reported as unknown unless it is {@code description},
     * {@code input_schema} or {@code name}.
     */
    private static void fields(JsonNode object, String path, String schemaPath, Set<String> metadata,
                               List<Segment> segments, TreeSet<String> unknown) {
        if (!object.isObject()) {
            wrongType(object, path, schemaPath, segments, unknown);
            return;
        }
        for (Map.Entry<String, JsonNode> field : object.properties()) {
            final String key = field.getKey();
            if (metadata.contains(key)) {
                continue;
            }
            label(field.getValue(), path + FallbackAdapter.keyPath(key), Source.UNKNOWN, segments);
            if (!Set.of("description", "input_schema", "name").contains(key)) {
                unknown.add(schemaPath + schemaKey(key));
            }
        }
    }

    /** A value of the wrong JSON type for the schema: labeled UNKNOWN in full and reported as {@code schemaPath(type)}. */
    private static void wrongType(JsonNode node, String path, String schemaPath, List<Segment> segments,
                                  TreeSet<String> unknown) {
        label(node, path, Source.UNKNOWN, segments);
        unknown.add(schemaPath + "(" + node.getNodeType().name().toLowerCase() + ")");
    }

    /** Every string under {@code node}, labeled {@code source}. */
    private static void label(JsonNode node, String location, Source source, List<Segment> segments) {
        final List<Segment> found = new ArrayList<>();
        FallbackAdapter.json(node, location, Direction.OUTBOUND, found);
        found.forEach(s -> segments.add(new Segment(source, s.direction(), s.text(), s.location())));
    }

    private static String schemaKey(String key) {
        return EndpointRouter.isIdLike(key) ? "[*]" : FallbackAdapter.keyPath(key);
    }
}
