package dev.llmfirewall.collector.parse;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.zip.GZIPInputStream;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;

/**
 * Undoes Content-Encoding: the proxy captures bodies still encoded. Supported codings
 * are identity, gzip (and x-gzip) and deflate, either zlib-wrapped as the RFC says or
 * raw as some servers send it. Stacked codings ({@code gzip, deflate}) are undone in
 * reverse header order. Coding names ignore case.
 *
 * <p>Each decoding step stops at {@code maxDecodedBytes}, so a decompression bomb cannot
 * exhaust memory; the prefix is returned with {@code truncated} set. A stream that ends
 * early, as a capped capture usually does, gives what was decoded with {@code incomplete}
 * set.
 */
public final class ContentDecoder {

    /** The decoded body. {@code truncated}: cut at the cap. {@code incomplete}: the encoded input ended mid-stream. */
    public record Decoded(byte[] data, boolean truncated, boolean incomplete) {}

    private final int maxDecodedBytes;

    /** @throws IllegalArgumentException if {@code maxDecodedBytes} is not positive */
    public ContentDecoder(int maxDecodedBytes) {
        if (maxDecodedBytes <= 0) {
            throw new IllegalArgumentException("maxDecodedBytes must be positive: " + maxDecodedBytes);
        }
        this.maxDecodedBytes = maxDecodedBytes;
    }

    /**
     * @param contentEncoding the raw header value, or null for identity
     * @throws ParseException {@code decode:unsupported} for a coding not listed above,
     *     or {@code decode:corrupt} for input that is not valid in its coding
     */
    public Decoded decode(byte[] body, String contentEncoding) throws ParseException {
        final List<String> codings = codings(contentEncoding);
        byte[] data = body;
        boolean truncated = false;
        boolean incomplete = false;
        for (int i = codings.size() - 1; i >= 0; i--) {
            final Decoded step = decodeOne(codings.get(i), data);
            data = step.data();
            truncated |= step.truncated();
            incomplete |= step.incomplete();
        }
        if (codings.isEmpty() && data.length > maxDecodedBytes) {
            return new Decoded(Arrays.copyOf(data, maxDecodedBytes), true, false);
        }
        return new Decoded(data, truncated, incomplete);
    }

    private static List<String> codings(String header) {
        final List<String> out = new ArrayList<>();
        if (header == null) {
            return out;
        }
        for (String part : header.split(",")) {
            final String coding = part.trim().toLowerCase(Locale.ROOT);
            if (!coding.isEmpty() && !coding.equals("identity")) {
                out.add(coding);
            }
        }
        return out;
    }

    private Decoded decodeOne(String coding, byte[] data) throws ParseException {
        final ByteArrayInputStream in = new ByteArrayInputStream(data);
        final Inflater inflater = coding.equals("deflate") ? new Inflater(!isZlibHeader(data)) : null;
        try (InputStream decoded = switch (coding) {
                case "gzip", "x-gzip" -> new GZIPInputStream(in);
                case "deflate" -> new InflaterInputStream(in, inflater);
                default -> throw new ParseException("decode:unsupported");
            }) {
            return readCapped(decoded);
        } catch (EOFException e) {
            return new Decoded(new byte[0], false, true);  // Too short even for the gzip header.
        } catch (IOException e) {
            throw new ParseException("decode:corrupt");
        } finally {
            if (inflater != null) {
                inflater.end();
            }
        }
    }

    /** RFC 1950: compression method 8, and the first two bytes are a multiple of 31. */
    private static boolean isZlibHeader(byte[] data) {
        return data.length >= 2 && (data[0] & 0x0f) == 8 && (((data[0] & 0xff) << 8) | (data[1] & 0xff)) % 31 == 0;
    }

    /** Reads at most one byte past the cap. @throws IOException for corrupt input */
    private Decoded readCapped(InputStream in) throws IOException {
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        final byte[] buffer = new byte[8192];
        try {
            int n;
            while ((n = in.read(buffer, 0, Math.min(buffer.length, maxDecodedBytes + 1 - out.size()))) >= 0) {
                out.write(buffer, 0, n);
                if (out.size() > maxDecodedBytes) {
                    return new Decoded(Arrays.copyOf(out.toByteArray(), maxDecodedBytes), true, false);
                }
            }
            return new Decoded(out.toByteArray(), false, false);
        } catch (EOFException e) {
            return new Decoded(out.toByteArray(), false, true);
        }
    }
}
