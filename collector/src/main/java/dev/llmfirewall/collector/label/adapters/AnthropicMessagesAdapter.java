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
 * {@code POST /v1/messages} on api.anthropic.com, the public Messages API that Claude
 * Code uses. This is the request side (mapping v1):
 * <ul>
 *   <li>{@code system}, as a string or {@code [].text}: UNKNOWN. Claude Code puts repo
 *       files such as CLAUDE.md and environment details there, which may be untrusted.</li>
 *   <li>user turns' text, as a string or {@code text} blocks: UNKNOWN. Clients insert
 *       file contents and reminders into user text, so it cannot be proven typed.</li>
 *   <li>assistant turns' text, as a string or {@code text} blocks: MODEL_OUTPUT (history
 *       being re-sent).</li>
 * </ul>
 * Known metadata fields (model, limits, flags, roles, block types, cache control) carry
 * no text and give no segment. Every other field is labeled UNKNOWN in full, as
 * {@link FallbackAdapter} does, and its path is reported as unknown. Stateless and thread-safe.
 */
public final class AnthropicMessagesAdapter {

    public static final String ID = "anthropic.messages";
    public static final int VERSION = 1;

    private static final Set<String> METADATA = Set.of("model", "max_tokens", "stream", "temperature", "top_p", "top_k",
        "metadata", "thinking", "output_config", "context_management", "diagnostics", "thread", "tool_choice",
        "stop_sequences", "service_tier");
    private static final Set<String> BLOCK_METADATA = Set.of("type", "cache_control");

    /** Labels a request body. Non-JSON parts are labeled by {@link FallbackAdapter} and reported as unknown. */
    public LabelResult labelRequest(ParsedBody body) {
        final Labels out = new Labels();
        Optional<String> model = Optional.empty();
        for (ParsedPart part : body.parts()) {
            if (part.kind() != ParsedPart.Kind.JSON || !part.json().isObject()) {
                out.segments.addAll(new FallbackAdapter().segments(new ParsedBody(List.of(part), List.of(), false),
                                                                   Direction.OUTBOUND));
                out.unknown.add(part.location() + ":" + part.kind().name().toLowerCase());
                continue;
            }
            final String at = part.location() + ":$";
            for (Map.Entry<String, JsonNode> field : part.json().properties()) {
                final String key = field.getKey();
                final JsonNode value = field.getValue();
                final String path = at + "." + key;
                switch (key) {
                    case "system" -> textOrBlocks(value, path, Source.UNKNOWN, out);
                    case "messages" -> messages(value, path, out);
                    default -> {
                        if (METADATA.contains(key)) {
                            if (key.equals("model") && value.isTextual()) {
                                model = Optional.of(value.textValue());
                            }
                        } else {
                            out.unknown(value, at + FallbackAdapter.keyPath(key), "$" + schemaKey(key));
                        }
                    }
                }
            }
        }
        final boolean toolResults = out.segments.stream().anyMatch(s -> s.source() == Source.TOOL_RESULT);
        return new LabelResult(List.copyOf(out.segments), Set.copyOf(out.unknown),
                               new LabelResult.Attributes(model, toolResults));
    }

    private static void messages(JsonNode messages, String path, Labels out) {
        for (int i = 0; i < messages.size(); i++) {
            final JsonNode message = messages.get(i);
            final String at = path + "[" + i + "]";
            final boolean assistant = message.path("role").asText().equals("assistant");
            for (Map.Entry<String, JsonNode> field : message.properties()) {
                switch (field.getKey()) {
                    case "role", "output_config", "cache_control" -> {
                        // Metadata.
                    }
                    case "content" -> {
                        if (field.getValue().isTextual()) {
                            out.add(assistant ? Source.MODEL_OUTPUT : Source.UNKNOWN, field.getValue().textValue(),
                                    at + ".content");
                        } else {
                            blocks(field.getValue(), at + ".content", assistant, out);
                        }
                    }
                    default -> out.unknown(field.getValue(), at + FallbackAdapter.keyPath(field.getKey()),
                                           "$.messages[]" + schemaKey(field.getKey()));
                }
            }
        }
    }

    private static void blocks(JsonNode blocks, String path, boolean assistant, Labels out) {
        for (int i = 0; i < blocks.size(); i++) {
            final JsonNode block = blocks.get(i);
            final String at = path + "[" + i + "]";
            final String type = block.path("type").asText();
            for (Map.Entry<String, JsonNode> field : block.properties()) {
                final String key = field.getKey();
                final JsonNode value = field.getValue();
                final String fieldPath = at + FallbackAdapter.keyPath(key);
                if (BLOCK_METADATA.contains(key)) {
                    continue;
                }
                switch (type + "." + key) {
                    case "text.text" -> out.add(assistant ? Source.MODEL_OUTPUT : Source.UNKNOWN, value.asText(), fieldPath);
                    default -> out.unknown(value, fieldPath, "$.messages[].content[](" + safeType(type) + ")" + schemaKey(key));
                }
            }
        }
    }

    /** A string, or blocks: every string in them except metadata is labeled {@code source}. */
    private static void textOrBlocks(JsonNode value, String path, Source source, Labels out) {
        if (!value.isArray()) {
            out.json(value, path, source);
            return;
        }
        for (int i = 0; i < value.size(); i++) {
            final JsonNode block = value.get(i);
            final String at = path + "[" + i + "]";
            for (Map.Entry<String, JsonNode> field : block.properties()) {
                final String key = field.getKey();
                if (!BLOCK_METADATA.contains(key)) {
                    out.json(field.getValue(), at + FallbackAdapter.keyPath(key), source);
                }
            }
        }
    }


    private static String schemaKey(String key) {
        return EndpointRouter.isIdLike(key) ? "[*]" : FallbackAdapter.keyPath(key);
    }

    private static String safeType(String type) {
        return type.matches("[A-Za-z0-9_-]{1,64}") ? type : "*";
    }

    /** The segments and unknown paths being collected. */
    private static final class Labels {
        final List<Segment> segments = new ArrayList<>();
        final TreeSet<String> unknown = new TreeSet<>();

        void add(Source source, String text, String location) {
            if (!text.isEmpty()) {
                segments.add(new Segment(source, Direction.OUTBOUND, text, location));
            }
        }

        /** Every string under {@code node}, labeled {@code source}. */
        void json(JsonNode node, String location, Source source) {
            final List<Segment> found = new ArrayList<>();
            FallbackAdapter.json(node, location, Direction.OUTBOUND, found);
            found.forEach(s -> segments.add(new Segment(source, s.direction(), s.text(), s.location())));
        }

        /** A field outside the schema: labeled UNKNOWN in full, and its schema path reported. */
        void unknown(JsonNode node, String location, String schemaPath) {
            FallbackAdapter.json(node, location, Direction.OUTBOUND, segments);
            unknown.add(schemaPath);
        }
    }
}
