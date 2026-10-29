package dev.llmfirewall.collector.parse;

import dev.llmfirewall.collector.coverage.CoverageCounters;
import dev.llmfirewall.collector.coverage.CoverageMetric;
import dev.llmfirewall.proto.v1.Body;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Locale;

/**
 * Parses one captured body: undoes its Content-Encoding, then dispatches on its media type.
 * <ul>
 *   <li>JSON types ({@link JsonBodyParser#supports}): one JSON part.</li>
 *   <li>{@code text/event-stream}: one SSE_STREAM part with its events.</li>
 *   <li>other {@code text/*} types: one TEXT part, read as UTF-8.</li>
 *   <li>anything else: one BINARY_SKIPPED part, counted as BODY_SKIPPED[media type]
 *       (or {@code <none>} with no Content-Type).</li>
 * </ul>
 * An omitted body (metadata_only mode) or an empty one gives {@link ParsedBody#EMPTY}. A
 * decode or parse failure gives no parts and one failure code, counted as
 * PARSE_FAILURE[code]. Thread-safe.
 */
public final class ParserRegistry {

    private final ContentDecoder decoder;
    private final JsonBodyParser json;
    private final SseStreamParser sse;
    private final CoverageCounters coverage;

    public ParserRegistry(ContentDecoder decoder, JsonBodyParser json, SseStreamParser sse, CoverageCounters coverage) {
        this.decoder = decoder;
        this.json = json;
        this.sse = sse;
        this.coverage = coverage;
    }

    /**
     * @param contentType     the Content-Type header value, or null
     * @param contentEncoding the Content-Encoding header value, or null
     * @param location        the location given to the parts
     */
    public ParsedBody parseBody(Body body, String contentType, String contentEncoding, String location) {
        if (body.getOmitted() || body.getData().isEmpty()) {
            return ParsedBody.EMPTY;
        }
        final ContentDecoder.Decoded decoded;
        try {
            decoded = decoder.decode(body.getData().toByteArray(), contentEncoding);
        } catch (ParseException e) {
            return failed(e.code(), body.getTruncated());
        }
        final boolean incomplete = body.getTruncated() || decoded.truncated() || decoded.incomplete();
        final String mediaType = mediaType(contentType);
        final ParsedPart part;
        if (JsonBodyParser.supports(contentType)) {
            try {
                part = new ParsedPart(ParsedPart.Kind.JSON, location, mediaType, json.parse(decoded.data()), null, null);
            } catch (ParseException e) {
                return failed(e.code(), incomplete);
            }
        } else if (mediaType.equals("text/event-stream")) {
            part = new ParsedPart(ParsedPart.Kind.SSE_STREAM, location, mediaType, null, null, sse.events(decoded.data()));
        } else if (mediaType.startsWith("text/")) {
            part = new ParsedPart(ParsedPart.Kind.TEXT, location, mediaType, null,
                                  new String(decoded.data(), StandardCharsets.UTF_8), null);
        } else {
            coverage.increment(CoverageMetric.BODY_SKIPPED, mediaType.isEmpty() ? "<none>" : mediaType);
            part = new ParsedPart(ParsedPart.Kind.BINARY_SKIPPED, location, mediaType, null, null, null);
        }
        return new ParsedBody(List.of(part), List.of(), incomplete);
    }

    private ParsedBody failed(String code, boolean incomplete) {
        coverage.increment(CoverageMetric.PARSE_FAILURE, code);
        return new ParsedBody(List.of(), List.of(code), incomplete);
    }

    /** Lower-cased, without parameters; empty when there is no Content-Type. */
    static String mediaType(String contentType) {
        if (contentType == null) {
            return "";
        }
        final int semicolon = contentType.indexOf(';');
        return (semicolon < 0 ? contentType : contentType.substring(0, semicolon)).trim().toLowerCase(Locale.ROOT);
    }
}
