package dev.llmfirewall.collector.parse;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.StreamReadConstraints;
import com.fasterxml.jackson.core.exc.StreamConstraintsException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.util.Locale;

/**
 * Parses JSON bodies into a Jackson tree. Untrusted input is bounded by the config's
 * nesting-depth limit and string-length limit, which applies to keys as well as values. The whole body must be one JSON value:
 * content after it is a syntax error. A truncated capture usually ends mid-value and
 * so fails with {@code json:syntax}; the capture's own truncated flag tells the two apart.
 * Thread-safe.
 */
public final class JsonBodyParser {

    private final ObjectMapper mapper;

    /** @throws IllegalArgumentException if either limit is not positive */
    public JsonBodyParser(int maxNestingDepth, int maxStringLength) {
        if (maxNestingDepth <= 0 || maxStringLength <= 0) {
            throw new IllegalArgumentException("JSON limits must be positive: depth " + maxNestingDepth
                                               + ", string length " + maxStringLength);
        }
        final StreamReadConstraints limits = StreamReadConstraints.builder()
            .maxNestingDepth(maxNestingDepth)
            .maxStringLength(maxStringLength)
            .maxNameLength(maxStringLength)
            .build();
        this.mapper = new ObjectMapper(JsonFactory.builder().streamReadConstraints(limits).build())
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
    }

    /** Whether a Content-Type names JSON: {@code application/json} or any {@code +json} type, ignoring case and parameters. */
    public static boolean supports(String contentType) {
        if (contentType == null) {
            return false;
        }
        final int semicolon = contentType.indexOf(';');
        final String type = (semicolon < 0 ? contentType : contentType.substring(0, semicolon)).trim()
            .toLowerCase(Locale.ROOT);
        return type.equals("application/json") || (type.endsWith("+json") && type.indexOf('/') > 0);
    }

    /**
     * @param decoded the body after content decoding, in any JSON encoding Jackson detects (UTF-8 in practice)
     * @throws ParseException {@code json:empty} for a body with no value, {@code json:limit}
     *     past a nesting or string limit, or {@code json:syntax} for anything else invalid
     */
    public JsonNode parse(byte[] decoded) throws ParseException {
        final JsonNode tree;
        try {
            tree = mapper.readTree(decoded);
        } catch (StreamConstraintsException e) {
            throw new ParseException("json:limit");
        } catch (IOException e) {
            throw new ParseException("json:syntax");
        }
        if (tree == null || tree.isMissingNode()) {
            throw new ParseException("json:empty");
        }
        return tree;
    }
}
