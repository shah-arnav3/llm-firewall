package dev.llmfirewall.collector.parse;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

/**
 * Reassembles a streamed reply in the Anthropic Messages event grammar
 * ({@code message_start}, {@code content_block_start}, {@code content_block_delta},
 * {@code content_block_stop}, {@code message_delta}, {@code message_stop}) into content
 * blocks, ordered by block index. Each event's data is parsed with the given JSON parser,
 * so its limits apply; the event's {@code type} field, not its SSE event name, decides
 * what it is.
 *
 * <ul>
 *   <li>{@code text}, {@code thinking}, {@code tool_use} and {@code server_tool_use} blocks
 *       keep their own types. Their text is the concatenated {@code text},
 *       {@code thinking} or {@code partial_json} deltas; tool blocks also carry the tool
 *       name, which is metadata, not content.</li>
 *   <li>Any other block type becomes {@code unknown:<type>}, and its text is the
 *       {@code content} it started with (as JSON) followed by the raw JSON of each delta,
 *       so nothing it carried escapes scanning.</li>
 *   <li>Citations, on a known block's start event or in {@code citations_delta} deltas, are
 *       collected into the block's {@code citations}, not its text.</li>
 *   <li>Deltas for a block whose start was never seen are kept, as {@code unknown:missing_start}.</li>
 *   <li>{@code signature_delta} deltas are opaque and dropped.</li>
 * </ul>
 * A block is complete once its {@code content_block_stop} arrives. The reply is complete
 * only if {@code message_stop} arrived and every event was complete and parsed.
 */
public final class SseReplyAssembler {

    /**
     * @param index    content block index
     * @param type     {@code text}, {@code thinking}, {@code tool_use}, {@code server_tool_use} or {@code unknown:<type>}
     * @param text     the block's concatenated content
     * @param toolName for tool blocks, the tool name; otherwise empty
     * @param citations the block's citations as one JSON array, from its start event and its
     *                  {@code citations_delta} deltas; empty if it has none. They quote sources,
     *                  so they are kept apart from the block's own text.
     */
    public record Block(int index, String type, String text, String toolName, boolean complete, String citations) {

        /** A block without citations. */
        public Block(int index, String type, String text, String toolName, boolean complete) {
            this(index, type, text, toolName, complete, "");
        }
    }

    /** {@code model} and {@code stopReason} are empty when the stream did not carry them. */
    public record AssembledReply(String model, String stopReason, List<Block> blocks, boolean complete) {}

    private static final Set<String> KNOWN_TYPES = Set.of("text", "thinking", "tool_use", "server_tool_use");

    private final JsonBodyParser json;

    public SseReplyAssembler(JsonBodyParser json) {
        this.json = json;
    }

    public AssembledReply assemble(List<SseStreamParser.SseEvent> events) {
        final Map<Integer, BlockBuilder> blocks = new TreeMap<>();
        String model = "";
        String stopReason = "";
        boolean stopped = false;
        boolean intact = true;
        for (SseStreamParser.SseEvent event : events) {
            final JsonNode data;
            try {
                data = json.parse(event.data().getBytes(StandardCharsets.UTF_8));
            } catch (ParseException e) {
                intact = false;
                continue;
            }
            intact &= event.complete();
            final int index = data.path("index").asInt(-1);
            switch (data.path("type").asText()) {
                case "message_start" -> model = data.at("/message/model").asText("");
                case "content_block_start" -> blocks.put(index, BlockBuilder.start(index, data.path("content_block")));
                case "content_block_delta" -> blocks.computeIfAbsent(index, i -> BlockBuilder.start(i, missingStart()))
                    .delta(data.path("delta"));
                case "content_block_stop" -> {
                    final BlockBuilder block = blocks.get(index);
                    if (block != null) {
                        block.complete = true;
                    }
                }
                case "message_delta" -> stopReason = data.at("/delta/stop_reason").asText(stopReason);
                case "message_stop" -> stopped = true;
                default -> {
                    // ping, error and event types this grammar does not define carry no reply content.
                }
            }
        }
        final List<Block> out = new ArrayList<>();
        blocks.values().forEach(b -> out.add(b.build()));
        return new AssembledReply(model, stopReason, out, stopped && intact);
    }

    /** A block whose start event was lost: its deltas are still kept, as an unknown type. */
    private static JsonNode missingStart() {
        return JsonNodeFactory.instance.objectNode().put("type", "missing_start");
    }

    private static final class BlockBuilder {
        private final int index;
        private final String type;
        private final String toolName;
        private final StringBuilder text = new StringBuilder();
        private final ArrayNode citations = JsonNodeFactory.instance.arrayNode();
        private boolean complete;

        private BlockBuilder(int index, String type, String toolName) {
            this.index = index;
            this.type = type;
            this.toolName = toolName;
        }

        static BlockBuilder start(int index, JsonNode block) {
            final String rawType = block.path("type").asText("");
            final boolean known = KNOWN_TYPES.contains(rawType);
            final BlockBuilder builder = new BlockBuilder(index, known ? rawType : "unknown:" + rawType,
                                                          rawType.endsWith("tool_use") ? block.path("name").asText("") : "");
            if (known) {
                builder.text.append(block.path(rawType.equals("thinking") ? "thinking" : "text").asText(""));
                if (block.path("citations").isArray()) {
                    builder.citations.addAll((ArrayNode) block.get("citations"));
                }
            } else if (block.has("content")) {
                builder.text.append(block.get("content").toString());
            }
            return builder;
        }

        void delta(JsonNode delta) {
            switch (delta.path("type").asText()) {
                case "text_delta" -> text.append(delta.path("text").asText(""));
                case "thinking_delta" -> text.append(delta.path("thinking").asText(""));
                case "input_json_delta" -> text.append(delta.path("partial_json").asText(""));
                case "citations_delta" -> citations.add(delta.path("citation"));
                case "signature_delta" -> {
                    // An opaque signature over the thinking block, not content.
                }
                default -> text.append(delta.toString());
            }
        }

        Block build() {
            return new Block(index, type, text.toString(), toolName, complete, citations.isEmpty() ? "" : citations.toString());
        }
    }
}
