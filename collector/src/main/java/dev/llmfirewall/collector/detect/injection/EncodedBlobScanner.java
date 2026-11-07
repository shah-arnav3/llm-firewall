package dev.llmfirewall.collector.detect.injection;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;

/**
 * Finds encoded runs that decode to readable text, where an instruction can hide from a
 * reviewer. A run is a maximal sequence of:
 * <ul>
 *   <li>hex digits, of even length;</li>
 *   <li>otherwise base64 or base64url characters, with up to two trailing {@code =};</li>
 *   <li>percent-escapes ({@code %XX}).</li>
 * </ul>
 * A run is reported when it decodes to at least {@code minDecodedBytes} bytes and its first
 * {@link #SAMPLE_BYTES} decoded bytes are valid UTF-8 with at least {@link #MIN_READABLE}
 * of the characters not control characters. Only that sample is decoded, so a large image
 * or other binary blob costs a few kilobytes of work. Thread-safe.
 */
final class EncodedBlobScanner {

    static final int SAMPLE_BYTES = 3072;
    static final double MIN_READABLE = 0.95;

    private final int minDecodedBytes;

    /** @throws IllegalArgumentException if {@code minDecodedBytes} is less than 1 */
    EncodedBlobScanner(int minDecodedBytes) {
        if (minDecodedBytes < 1) {
            throw new IllegalArgumentException("minDecodedBytes must be at least 1: " + minDecodedBytes);
        }
        this.minDecodedBytes = minDecodedBytes;
    }

    /** @return the {start, end} UTF-16 spans of the reported runs, in text order */
    List<int[]> find(String text) {
        final List<int[]> out = new ArrayList<>();
        int i = 0;
        while (i < text.length()) {
            if (isPercentEscape(text, i)) {
                int end = i;
                while (isPercentEscape(text, end)) {
                    end += 3;
                }
                final int count = (end - i) / 3;
                if (count >= minDecodedBytes && readable(percentSample(text, i, Math.min(count, SAMPLE_BYTES)))) {
                    out.add(new int[] {i, end});
                }
                i = end;
            } else if (isBase64(text.charAt(i))) {
                int body = i;
                while (body < text.length() && isBase64(text.charAt(body))) {
                    body++;
                }
                int end = body;
                while (end < text.length() && end - body < 2 && text.charAt(end) == '=') {
                    end++;
                }
                if (encodedRun(text, i, body)) {
                    out.add(new int[] {i, end});
                }
                i = end;
            } else {
                i++;
            }
        }
        return out;
    }

    /** Whether {@code text[start, end)}, a run of base64 characters, decodes to readable text. */
    private boolean encodedRun(String text, int start, int end) {
        final int length = end - start;
        if (length % 2 == 0 && allHex(text, start, end)) {
            return length / 2 >= minDecodedBytes
                   && readable(HexFormat.of().parseHex(text, start, start + Math.min(length, 2 * SAMPLE_BYTES)));
        }
        if ((long) length * 3 / 4 < minDecodedBytes) {
            return false;
        }
        // A whole number of 4-character groups decodes without padding.
        final int sampleChars = Math.min(length, SAMPLE_BYTES / 3 * 4) / 4 * 4;
        final String sample = text.substring(start, start + sampleChars).replace('-', '+').replace('_', '/');
        try {
            return readable(Base64.getDecoder().decode(sample));
        } catch (IllegalArgumentException mixedAlphabets) {
            return false;
        }
    }

    private static byte[] percentSample(String text, int start, int count) {
        final byte[] out = new byte[count];
        for (int k = 0; k < count; k++) {
            out[k] = (byte) HexFormat.fromHexDigits(text, start + 3 * k + 1, start + 3 * k + 3);
        }
        return out;
    }

    /** Valid UTF-8, allowing a sequence cut off by the sample's end, and mostly not control characters. */
    private static boolean readable(byte[] bytes) {
        final CharsetDecoder decoder = StandardCharsets.UTF_8.newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT);
        final CharBuffer chars = CharBuffer.allocate(bytes.length);
        if (decoder.decode(ByteBuffer.wrap(bytes), chars, false).isError()) {
            return false;
        }
        chars.flip();
        if (!chars.hasRemaining()) {
            return false;
        }
        final long control = chars.chars().filter(c -> Character.isISOControl(c) && c != '\t' && c != '\n' && c != '\r').count();
        return control <= (1 - MIN_READABLE) * chars.length();
    }

    private static boolean isPercentEscape(String text, int i) {
        return i + 2 < text.length() && text.charAt(i) == '%' && isHex(text.charAt(i + 1)) && isHex(text.charAt(i + 2));
    }

    private static boolean allHex(String text, int start, int end) {
        for (int k = start; k < end; k++) {
            if (!isHex(text.charAt(k))) {
                return false;
            }
        }
        return true;
    }

    private static boolean isHex(int c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    }

    private static boolean isBase64(char c) {
        return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
               || c == '+' || c == '/' || c == '-' || c == '_';
    }
}
