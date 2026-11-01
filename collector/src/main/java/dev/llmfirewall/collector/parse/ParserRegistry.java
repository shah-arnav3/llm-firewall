package dev.llmfirewall.collector.parse;

import dev.llmfirewall.collector.coverage.CoverageCounters;
import dev.llmfirewall.collector.coverage.CoverageMetric;
import dev.llmfirewall.proto.v1.Body;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Parses one captured body: undoes its Content-Encoding, then dispatches on its media type.
 * <ul>
 *   <li>JSON types ({@link JsonBodyParser#supports}): one JSON part.</li>
 *   <li>{@code text/event-stream}: one SSE_STREAM part with its events.</li>
 *   <li>{@code multipart/form-data}: one part per form part, at {@code <location>:part[i]}.
 *       A plain field becomes TEXT, or JSON if its own type is JSON. A file becomes TEXT
 *       if its type is {@code text/*}, or it has no type or {@code application/octet-stream}
 *       and is valid UTF-8 without NUL bytes; otherwise it is BINARY_SKIPPED and counted
 *       as BODY_SKIPPED[{@code file:<type>}]. Files carry a {@link ParsedPart.FileInfo};
 *       their names are never kept. A body cut before its closing delimiter is incomplete.</li>
 *   <li>other {@code text/*} types: one TEXT part, read as UTF-8.</li>
 *   <li>anything else: one BINARY_SKIPPED part, counted as BODY_SKIPPED[media type]
 *       (or {@code <none>} with no Content-Type).</li>
 * </ul>
 * An omitted body (metadata_only mode) or an empty one gives {@link ParsedBody#EMPTY}. A
 * decode or parse failure gives no parts and one failure code, counted as
 * PARSE_FAILURE[code]. Thread-safe.
 */
public final class ParserRegistry {

    /** Form parts read from one multipart body at most. */
    static final int MAX_MULTIPART_PARTS = 100;

    private final ContentDecoder decoder;
    private final MultipartBodyParser multipart = new MultipartBodyParser(MAX_MULTIPART_PARTS);
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
        if (mediaType.equals("multipart/form-data")) {
            return multipart(decoded.data(), contentType, location, incomplete);
        }
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

    private ParsedBody multipart(byte[] data, String contentType, String location, boolean incomplete) {
        final MultipartBodyParser.Result result;
        try {
            result = multipart.parse(data, contentType);
        } catch (ParseException e) {
            return failed(e.code(), incomplete);
        }
        final List<ParsedPart> parts = new ArrayList<>();
        final List<String> failures = new ArrayList<>();
        for (int i = 0; i < result.parts().size(); i++) {
            final MultipartBodyParser.Part p = result.parts().get(i);
            final String at = location + ":part[" + i + "]";
            final String type = mediaType(p.contentType());
            if (p.filename() == null) {
                if (JsonBodyParser.supports(p.contentType())) {
                    try {
                        parts.add(new ParsedPart(ParsedPart.Kind.JSON, at, type, json.parse(p.data()), null, null));
                    } catch (ParseException e) {
                        coverage.increment(CoverageMetric.PARSE_FAILURE, e.code());
                        failures.add(e.code());
                    }
                } else {
                    parts.add(new ParsedPart(ParsedPart.Kind.TEXT, at, type, null,
                                             new String(p.data(), StandardCharsets.UTF_8), null));
                }
                continue;
            }
            final ParsedPart.FileInfo file = new ParsedPart.FileInfo(fileType(p.filename(), type), p.data().length);
            if (isText(type, p.data())) {
                parts.add(new ParsedPart(ParsedPart.Kind.TEXT, at, type, null,
                                         new String(p.data(), StandardCharsets.UTF_8), null, file));
            } else {
                coverage.increment(CoverageMetric.BODY_SKIPPED, "file:" + file.fileType());
                parts.add(new ParsedPart(ParsedPart.Kind.BINARY_SKIPPED, at, type, null, null, null, file));
            }
        }
        return new ParsedBody(List.copyOf(parts), List.copyOf(failures), incomplete || !result.complete());
    }

    private static boolean isText(String mediaType, byte[] data) {
        if (mediaType.startsWith("text/")) {
            return true;
        }
        if (!mediaType.isEmpty() && !mediaType.equals("application/octet-stream")) {
            return false;
        }
        for (byte b : data) {
            if (b == 0) {
                return false;
            }
        }
        try {
            StandardCharsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(data));
            return true;
        } catch (CharacterCodingException e) {
            return false;
        }
    }

    private static String fileType(String filename, String mediaType) {
        final int dot = filename.lastIndexOf('.');
        final String extension = dot < 0 ? "" : filename.substring(dot + 1).toLowerCase(Locale.ROOT);
        if (extension.matches("[a-z0-9]{1,10}")) {
            return extension;
        }
        return mediaType.isEmpty() ? "unknown" : mediaType;
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
