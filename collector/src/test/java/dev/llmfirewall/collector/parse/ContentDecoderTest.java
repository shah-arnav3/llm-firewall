package dev.llmfirewall.collector.parse;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.GZIPOutputStream;
import org.junit.jupiter.api.Test;

class ContentDecoderTest {

    private static final byte[] TEXT = "{\"prompt\":\"hello hello hello hello\"}".getBytes(StandardCharsets.UTF_8);

    private static byte[] gzip(byte[] data) throws IOException {
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (GZIPOutputStream gz = new GZIPOutputStream(out)) {
            gz.write(data);
        }
        return out.toByteArray();
    }

    private static byte[] deflate(byte[] data, boolean raw) throws IOException {
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        final Deflater deflater = new Deflater(Deflater.DEFAULT_COMPRESSION, raw);
        try (DeflaterOutputStream d = new DeflaterOutputStream(out, deflater)) {
            d.write(data);
        } finally {
            deflater.end();
        }
        return out.toByteArray();
    }

    private final ContentDecoder decoder = new ContentDecoder(1 << 20);

    @Test
    void passesIdentityThrough() throws ParseException {
        for (String header : new String[] {null, "", "identity", " Identity "}) {
            final ContentDecoder.Decoded d = decoder.decode(TEXT, header);
            assertArrayEquals(TEXT, d.data(), header);
            assertFalse(d.truncated() || d.incomplete(), header);
        }
    }

    @Test
    void decodesGzipAndDeflate() throws Exception {
        assertArrayEquals(TEXT, decoder.decode(gzip(TEXT), "gzip").data());
        assertArrayEquals(TEXT, decoder.decode(gzip(TEXT), "X-GZIP").data());
        assertArrayEquals(TEXT, decoder.decode(deflate(TEXT, false), "deflate").data(), "zlib-wrapped");
        assertArrayEquals(TEXT, decoder.decode(deflate(TEXT, true), "deflate").data(), "raw");
    }

    /** The 3000-event SSE stream that src/test/resources/.../sse.br holds, brotli-compressed with the brotli CLI. */
    private static byte[] sse() {
        final StringBuilder out = new StringBuilder();
        for (int i = 0; i < 3000; i++) {
            out.append("data: {\"n\":").append(i).append("}\n\n");
        }
        return out.toString().getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] sseBrotli() throws IOException {
        try (var in = ContentDecoderTest.class.getResourceAsStream("sse.br")) {
            return in.readAllBytes();
        }
    }

    @Test
    void decodesBrotli() throws Exception {
        final ContentDecoder.Decoded d = decoder.decode(sseBrotli(), "br");
        assertArrayEquals(sse(), d.data());
        assertFalse(d.truncated() || d.incomplete());
    }

    @Test
    void capsABrotliBomb() throws Exception {
        final byte[] tenMiBOfZeros = Base64.getDecoder().decode("n///n/gnAOKxQCD3/hM=");
        final ContentDecoder.Decoded d = new ContentDecoder(1000).decode(tenMiBOfZeros, "br");
        assertEquals(1000, d.data().length);
        assertTrue(d.truncated());
    }

    @Test
    void aTruncatedBrotliBodyIsReportedAsCorrupt() throws Exception {
        final byte[] half = Arrays.copyOf(sseBrotli(), sseBrotli().length / 2);
        assertEquals("decode:corrupt", assertThrows(ParseException.class, () -> decoder.decode(half, "br")).code());
    }

    @Test
    void decodesStackedEncodingsInReverseOrder() throws Exception {
        final byte[] twice = gzip(deflate(TEXT, false));  // deflate applied first, so listed first.
        final ContentDecoder.Decoded d = decoder.decode(twice, "deflate, gzip");
        assertArrayEquals(TEXT, d.data());
        assertFalse(d.truncated() || d.incomplete());
    }

    @Test
    void capsOutputAgainstDecompressionBomb() throws Exception {
        final byte[] bomb = gzip(new byte[10 << 20]);  // 10 MiB of zeros, about 10 KiB compressed.
        final ContentDecoder.Decoded d = new ContentDecoder(1000).decode(bomb, "gzip");
        assertEquals(1000, d.data().length);
        assertTrue(d.truncated());
        assertFalse(d.incomplete());
    }

    @Test
    void capsAnIdentityBody() throws ParseException {
        final ContentDecoder.Decoded d = new ContentDecoder(5).decode(TEXT, null);
        assertArrayEquals(Arrays.copyOf(TEXT, 5), d.data());
        assertTrue(d.truncated());
    }

    @Test
    void returnsPrefixAndIncompleteForTruncatedStream() throws Exception {
        final byte[] big = new byte[100_000];
        for (int i = 0; i < big.length; i++) {
            big[i] = (byte) (i * 31 % 251);
        }
        final byte[] encoded = gzip(big);
        final ContentDecoder.Decoded d = decoder.decode(Arrays.copyOf(encoded, encoded.length / 2), "gzip");
        assertTrue(d.incomplete());
        assertFalse(d.truncated());
        assertTrue(d.data().length > 0);
        assertArrayEquals(Arrays.copyOf(big, d.data().length), d.data(), "a true prefix");
    }

    @Test
    void aBodyTooShortForTheGzipHeaderIsIncomplete() throws ParseException {
        final ContentDecoder.Decoded d = decoder.decode(new byte[] {0x1f, (byte) 0x8b}, "gzip");
        assertEquals(0, d.data().length);
        assertTrue(d.incomplete());
    }

    @Test
    void rejectsCorruptInput() {
        final ParseException e = assertThrows(ParseException.class,
                                              () -> decoder.decode("not gzip at all".getBytes(StandardCharsets.UTF_8), "gzip"));
        assertEquals("decode:corrupt", e.code());
    }

    @Test
    void rejectsUnknownEncoding() {
        for (String header : new String[] {"zstd", "compress", "gzip, rot13"}) {
            assertEquals("decode:unsupported", assertThrows(ParseException.class, () -> decoder.decode(TEXT, header)).code(),
                         header);
        }
    }
}
