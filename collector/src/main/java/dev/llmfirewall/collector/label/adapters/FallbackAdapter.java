package dev.llmfirewall.collector.label.adapters;

import com.fasterxml.jackson.databind.JsonNode;
import dev.llmfirewall.collector.label.Direction;
import dev.llmfirewall.collector.label.Segment;
import dev.llmfirewall.collector.label.Source;
import dev.llmfirewall.collector.parse.ParsedBody;
import dev.llmfirewall.collector.parse.ParsedPart;
import dev.llmfirewall.collector.parse.SseStreamParser;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Labels every piece of text in a body as UNKNOWN, so a body no adapter understands is
 * still scanned in full. Adapters also use it for the fields they do not recognise.
 * <ul>
 *   <li>JSON: every non-empty string value, at {@code <part>:$.a.b[2]}. A key that is
 *       not a plain identifier (letters, digits, {@code _} and {@code -}, at most 64)
 *       could carry text itself: it is emitted too, at {@code <path>(key)}, and written
 *       as {@code [*]} in paths, so locations stay content-free.</li>
 *   <li>TEXT: the whole text, at {@code <part>:text}.</li>
 *   <li>SSE_STREAM: each event's data, at {@code <part>:sse[i]}.</li>
 *   <li>BINARY_SKIPPED parts carry no text.</li>
 * </ul>
 * Empty strings are skipped. Stateless and thread-safe.
 */
public final class FallbackAdapter {

    private static final Pattern PLAIN_KEY = Pattern.compile("[A-Za-z0-9_-]{1,64}");

    /** The segments of one body, in body order. */
    public List<Segment> segments(ParsedBody body, Direction direction) {
        final List<Segment> out = new ArrayList<>();
        for (ParsedPart part : body.parts()) {
            switch (part.kind()) {
                case JSON -> json(part.json(), part.location() + ":$", direction, out);
                case TEXT -> add(out, direction, part.text(), part.location() + ":text");
                case SSE_STREAM -> {
                    for (SseStreamParser.SseEvent event : part.sseEvents()) {
                        add(out, direction, event.data(), part.location() + ":sse[" + event.index() + "]");
                    }
                }
                case BINARY_SKIPPED -> {
                    // Nothing was read from it.
                }
            }
        }
        return out;
    }

    /** Adds every string under {@code node}, whose location is {@code path}, as UNKNOWN. */
    public static void json(JsonNode node, String path, Direction direction, List<Segment> out) {
        if (node.isTextual()) {
            add(out, direction, node.textValue(), path);
        } else if (node.isArray()) {
            for (int i = 0; i < node.size(); i++) {
                json(node.get(i), path + "[" + i + "]", direction, out);
            }
        } else if (node.isObject()) {
            for (Map.Entry<String, JsonNode> field : node.properties()) {
                final String child = path + keyPath(field.getKey());
                if (!PLAIN_KEY.matcher(field.getKey()).matches()) {
                    add(out, direction, field.getKey(), child + "(key)");
                }
                json(field.getValue(), child, direction, out);
            }
        }
    }

    /** The path step for an object key: {@code .key}, or {@code [*]} for a key that is not a plain identifier. */
    public static String keyPath(String key) {
        return PLAIN_KEY.matcher(key).matches() ? "." + key : "[*]";
    }

    private static void add(List<Segment> out, Direction direction, String text, String location) {
        if (text != null && !text.isEmpty()) {
            out.add(new Segment(Source.UNKNOWN, direction, text, location));
        }
    }
}
