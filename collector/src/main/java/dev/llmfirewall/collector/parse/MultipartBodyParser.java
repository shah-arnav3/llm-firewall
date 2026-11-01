package dev.llmfirewall.collector.parse;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Splits a multipart/form-data body (RFC 7578) into its parts, by the boundary named in
 * the Content-Type. Each part keeps its form-field name, its filename (null for a plain
 * field), its own Content-Type (null if absent) and its bytes. The preamble and epilogue
 * are ignored. A body that ends before the closing delimiter, as a truncated capture
 * does, gives the parts so far, the last one cut short, with {@code complete} false.
 * Stateless and thread-safe.
 */
public final class MultipartBodyParser {

    /** One part. {@code filename} is only for deriving a file type; callers must not keep it. */
    public record Part(String name, String filename, String contentType, byte[] data) {}

    /** The parts in body order; {@code complete} is false if the closing delimiter was missing. */
    public record Result(List<Part> parts, boolean complete) {}

    private static final Pattern BOUNDARY = Pattern.compile("(?i)[;\\s]boundary=(\"([^\"]{1,70})\"|([^;\\s]{1,70}))");
    private static final Pattern NAME = Pattern.compile("(?i)(?:^|;)\\s*name=\"([^\"]*)\"");
    private static final Pattern FILENAME = Pattern.compile("(?i)(?:^|;)\\s*filename=\"([^\"]*)\"");
    private static final byte[] CRLF = {'\r', '\n'};
    private static final byte[] HEADER_END = {'\r', '\n', '\r', '\n'};

    private final int maxParts;

    /** @throws IllegalArgumentException if {@code maxParts} is not positive */
    public MultipartBodyParser(int maxParts) {
        if (maxParts <= 0) {
            throw new IllegalArgumentException("maxParts must be positive: " + maxParts);
        }
        this.maxParts = maxParts;
    }

    /**
     * @throws ParseException {@code multipart:no_boundary} if the Content-Type names none,
     *     {@code multipart:no_delimiter} if the body never starts a part, or
     *     {@code multipart:too_many_parts} past the limit
     */
    public Result parse(byte[] body, String contentType) throws ParseException {
        final Matcher m = contentType == null ? null : BOUNDARY.matcher(contentType);
        if (m == null || !m.find()) {
            throw new ParseException("multipart:no_boundary");
        }
        final byte[] delimiter = ("--" + (m.group(2) != null ? m.group(2) : m.group(3))).getBytes(StandardCharsets.ISO_8859_1);
        int start = indexOf(body, delimiter, 0);
        if (start < 0) {
            throw new ParseException("multipart:no_delimiter");
        }
        final byte[] next = concat(CRLF, delimiter);
        final List<Part> parts = new ArrayList<>();
        while (true) {
            int pos = start + delimiter.length;
            if (startsWith(body, pos, new byte[] {'-', '-'})) {
                return new Result(parts, true);
            }
            if (startsWith(body, pos, CRLF)) {
                pos += 2;
            }
            if (parts.size() == maxParts) {
                throw new ParseException("multipart:too_many_parts");
            }
            final int headersEnd = indexOf(body, HEADER_END, pos);
            if (headersEnd < 0) {
                return new Result(parts, false);  // Cut off inside the headers: nothing of this part's data arrived.
            }
            final String headers = new String(body, pos, headersEnd - pos, StandardCharsets.UTF_8);
            final int dataStart = headersEnd + HEADER_END.length;
            final int end = indexOf(body, next, dataStart);
            parts.add(part(headers, Arrays.copyOfRange(body, dataStart, end < 0 ? body.length : end)));
            if (end < 0) {
                return new Result(parts, false);
            }
            start = end + CRLF.length;
        }
    }

    private static Part part(String headers, byte[] data) {
        String name = "";
        String filename = null;
        String contentType = null;
        for (String line : headers.split("\r\n")) {
            final int colon = line.indexOf(':');
            if (colon < 0) {
                continue;
            }
            final String header = line.substring(0, colon).trim().toLowerCase(Locale.ROOT);
            final String value = line.substring(colon + 1).trim();
            if (header.equals("content-disposition")) {
                final Matcher n = NAME.matcher(value);
                name = n.find() ? n.group(1) : "";
                final Matcher f = FILENAME.matcher(value);
                filename = f.find() ? f.group(1) : null;
            } else if (header.equals("content-type")) {
                contentType = value;
            }
        }
        return new Part(name, filename, contentType, data);
    }

    private static boolean startsWith(byte[] body, int pos, byte[] prefix) {
        return pos + prefix.length <= body.length && Arrays.equals(body, pos, pos + prefix.length, prefix, 0, prefix.length);
    }

    private static int indexOf(byte[] body, byte[] needle, int from) {
        for (int i = Math.max(from, 0); i + needle.length <= body.length; i++) {
            if (startsWith(body, i, needle)) {
                return i;
            }
        }
        return -1;
    }

    private static byte[] concat(byte[] a, byte[] b) {
        final byte[] out = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }
}
