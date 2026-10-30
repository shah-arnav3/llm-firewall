package dev.llmfirewall.collector.label.adapters;

import com.fasterxml.jackson.databind.JsonNode;
import dev.llmfirewall.collector.label.Direction;
import dev.llmfirewall.collector.label.EndpointRouter;
import dev.llmfirewall.collector.label.LabelResult;
import dev.llmfirewall.collector.label.Segment;
import dev.llmfirewall.collector.label.Source;
import dev.llmfirewall.collector.parse.ParsedBody;
import dev.llmfirewall.collector.parse.ParsedPart;
import dev.llmfirewall.collector.parse.SseReplyAssembler;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;

/**
 * {@code POST /v1/messages} on api.anthropic.com, the public Messages API that Claude
 * Code uses (mapping v1). Requests:
 * <ul>
 *   <li>{@code system}, as a string or {@code [].text}: UNKNOWN. Claude Code puts repo
 *       files such as CLAUDE.md and environment details there, which may be untrusted.</li>
 *   <li>user turns' text, as a string or {@code text} blocks: UNKNOWN. Clients insert
 *       file contents and reminders into user text, so it cannot be proven typed.</li>
 *   <li>{@code tool_result} blocks, their content as a string or {@code [].text}: TOOL_RESULT.</li>
 *   <li>{@code document} blocks with a {@code text} source: ATTACHMENT. Image and base64
 *       document data is binary and not labeled.</li>
 *   <li>assistant turns' {@code text}, {@code thinking} and {@code tool_use} input: MODEL_OUTPUT
 *       (history being re-sent). Their {@code citations} quote sources: UNKNOWN.</li>
 *   <li>{@code tools[].description} and every string in {@code tools[].input_schema}, and
 *       every string in {@code safeguards}: UNKNOWN. Tool definitions can come from MCP
 *       servers; the safeguard context carries paths and git remotes.</li>
 * </ul>
 * Replies, either an SSE stream (reassembled by {@link SseReplyAssembler}) or one JSON
 * message, by content block:
 * <ul>
 *   <li>{@code text}, {@code thinking}, and {@code tool_use} or {@code server_tool_use}
 *       input: MODEL_OUTPUT.</li>
 *   <li>blocks whose type ends in {@code _tool_result} (web search, web fetch, code
 *       execution): SERVER_TOOL_RESULT, every string in their content. So are a block's
 *       {@code citations}, which quote the sources.</li>
 *   <li>any other block type: UNKNOWN, and reported as unknown.</li>
 * </ul>
 * Known metadata fields (model, limits, flags, roles, block types, ids, cache control,
 * usage, stop reasons) carry no text and give no segment. Every other field is labeled
 * UNKNOWN in full, as {@link FallbackAdapter} does, and its path is reported as unknown.
 * Thread-safe.
 */
public final class AnthropicMessagesAdapter {

    public static final String ID = "anthropic.messages";
    public static final int VERSION = 1;

    private static final Set<String> METADATA = Set.of("model", "max_tokens", "stream", "temperature", "top_p", "top_k",
        "metadata", "thinking", "output_config", "context_management", "diagnostics", "thread", "tool_choice",
        "stop_sequences", "service_tier");
    private static final Set<String> BLOCK_METADATA = Set.of("type", "id", "tool_use_id", "is_error", "cache_control",
        "name", "signature");
    private static final Set<String> TOOL_METADATA = Set.of("name", "type", "defer_loading", "eager_input_streaming", "model",
        "cache_control");

    private static final Set<String> REPLY_METADATA = Set.of("id", "type", "role", "model", "stop_reason", "stop_sequence",
        "stop_details", "usage", "container", "context_management", "diagnostics");

    private final SseReplyAssembler assembler;

    public AnthropicMessagesAdapter(SseReplyAssembler assembler) {
        this.assembler = assembler;
    }

    /** Labels a reply body. Parts that are neither JSON nor SSE are labeled by {@link FallbackAdapter} and reported as unknown. */
    public LabelResult labelResponse(ParsedBody body) {
        final Labels out = new Labels(Direction.INBOUND);
        Optional<String> model = Optional.empty();
        for (ParsedPart part : body.parts()) {
            if (part.kind() == ParsedPart.Kind.SSE_STREAM) {
                final SseReplyAssembler.AssembledReply reply = assembler.assemble(part.sseEvents());
                model = reply.model().isEmpty() ? model : Optional.of(reply.model());
                for (SseReplyAssembler.Block block : reply.blocks()) {
                    final String at = part.location() + ":sse:block[" + block.index() + "]";
                    final String type = block.type().replaceFirst("^unknown:", "");
                    final Source source = replySource(type);
                    out.add(source == null ? Source.UNKNOWN : source, block.text(), at);
                    out.add(Source.SERVER_TOOL_RESULT, block.citations(), at + ".citations");
                    if (source == null) {
                        out.unknown.add("sse:block(" + safeType(type) + ")");
                    }
                }
            } else if (part.kind() == ParsedPart.Kind.JSON && part.json().isObject()) {
                final String at = part.location() + ":$";
                for (Map.Entry<String, JsonNode> field : part.json().properties()) {
                    final String key = field.getKey();
                    if (key.equals("content")) {
                        replyBlocks(field.getValue(), at + ".content", out);
                    } else if (key.equals("model") && field.getValue().isTextual()) {
                        model = Optional.of(field.getValue().textValue());
                    } else if (!REPLY_METADATA.contains(key)) {
                        out.unknown(field.getValue(), at + FallbackAdapter.keyPath(key), "$" + schemaKey(key));
                    }
                }
            } else {
                out.segments.addAll(new FallbackAdapter().segments(new ParsedBody(List.of(part), List.of(), false),
                                                                   Direction.INBOUND));
                out.unknown.add(part.location() + ":" + part.kind().name().toLowerCase());
            }
        }
        return new LabelResult(List.copyOf(out.segments), Set.copyOf(out.unknown), new LabelResult.Attributes(model, false));
    }

    /** The source of a reply block's content, or null for a block type outside the schema. */
    private static Source replySource(String type) {
        if (type.equals("text") || type.equals("thinking") || type.equals("tool_use") || type.equals("server_tool_use")) {
            return Source.MODEL_OUTPUT;
        }
        return type.endsWith("_tool_result") ? Source.SERVER_TOOL_RESULT : null;
    }

    private static void replyBlocks(JsonNode blocks, String path, Labels out) {
        for (int i = 0; i < blocks.size(); i++) {
            final JsonNode block = blocks.get(i);
            final String at = path + "[" + i + "]";
            final String type = block.path("type").asText();
            final Source source = replySource(type);
            for (Map.Entry<String, JsonNode> field : block.properties()) {
                final String key = field.getKey();
                if (BLOCK_METADATA.contains(key)) {
                    continue;
                }
                if (key.equals("citations")) {
                    out.json(field.getValue(), at + ".citations", Source.SERVER_TOOL_RESULT);
                } else if (source == null) {
                    out.unknown(field.getValue(), at + FallbackAdapter.keyPath(key),
                                "$.content[](" + safeType(type) + ")" + schemaKey(key));
                } else {
                    out.json(field.getValue(), at + FallbackAdapter.keyPath(key), source);
                }
            }
        }
    }

    /** Labels a request body. Non-JSON parts are labeled by {@link FallbackAdapter} and reported as unknown. */
    public LabelResult labelRequest(ParsedBody body) {
        final Labels out = new Labels(Direction.OUTBOUND);
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
                    case "tools" -> tools(value, path, out);
                    case "safeguards" -> FallbackAdapter.json(value, path, Direction.OUTBOUND, out.segments);
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
                if (key.equals("citations")) {
                    out.json(value, fieldPath, Source.UNKNOWN);  // Quoted from sources: history, but untrusted.
                    continue;
                }
                switch (type + "." + key) {
                    case "text.text" -> out.add(assistant ? Source.MODEL_OUTPUT : Source.UNKNOWN, value.asText(), fieldPath);
                    case "thinking.thinking" -> out.add(Source.MODEL_OUTPUT, value.asText(), fieldPath);
                    case "tool_use.input" -> out.json(value, fieldPath, Source.MODEL_OUTPUT);
                    case "tool_result.content" -> textOrBlocks(value, fieldPath, Source.TOOL_RESULT, out);
                    case "document.source" -> {
                        if (value.path("type").asText().equals("text")) {
                            out.add(Source.ATTACHMENT, value.path("data").asText(), fieldPath + ".data");
                        }
                    }
                    case "image.source" -> {
                        // Binary data, not text.
                    }
                    default -> out.unknown(value, fieldPath, "$.messages[].content[](" + safeType(type) + ")" + schemaKey(key));
                }
            }
        }
    }

    /** A string, or blocks: every string in them except metadata and image data is labeled {@code source}. */
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
                final boolean binary = key.equals("source") && block.path("type").asText().equals("image");
                if (!binary && !BLOCK_METADATA.contains(key) && !key.equals("tool_name")) {
                    out.json(field.getValue(), at + FallbackAdapter.keyPath(key), source);
                }
            }
        }
    }

    private static void tools(JsonNode tools, String path, Labels out) {
        for (int i = 0; i < tools.size(); i++) {
            final String at = path + "[" + i + "]";
            for (Map.Entry<String, JsonNode> field : tools.get(i).properties()) {
                final String key = field.getKey();
                if (key.equals("description") || key.equals("input_schema")) {
                    out.json(field.getValue(), at + "." + key, Source.UNKNOWN);
                } else if (!TOOL_METADATA.contains(key)) {
                    out.unknown(field.getValue(), at + FallbackAdapter.keyPath(key), "$.tools[]" + schemaKey(key));
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
        final Direction direction;
        final List<Segment> segments = new ArrayList<>();
        final TreeSet<String> unknown = new TreeSet<>();

        Labels(Direction direction) {
            this.direction = direction;
        }

        void add(Source source, String text, String location) {
            if (!text.isEmpty()) {
                segments.add(new Segment(source, direction, text, location));
            }
        }

        /** Every string under {@code node}, labeled {@code source}. */
        void json(JsonNode node, String location, Source source) {
            final List<Segment> found = new ArrayList<>();
            FallbackAdapter.json(node, location, direction, found);
            found.forEach(s -> segments.add(new Segment(source, s.direction(), s.text(), s.location())));
        }

        /** A field outside the schema: labeled UNKNOWN in full, and its schema path reported. */
        void unknown(JsonNode node, String location, String schemaPath) {
            FallbackAdapter.json(node, location, direction, segments);
            unknown.add(schemaPath);
        }
    }
}
