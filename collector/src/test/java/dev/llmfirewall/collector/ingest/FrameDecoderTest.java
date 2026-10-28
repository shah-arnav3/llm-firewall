package dev.llmfirewall.collector.ingest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.protobuf.InvalidProtocolBufferException;
import dev.llmfirewall.proto.v1.Capture;
import dev.llmfirewall.proto.v1.Frame;
import dev.llmfirewall.proto.v1.StreamHello;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import org.junit.jupiter.api.Test;

class FrameDecoderTest {

    private static final int MAX = 1024;

    private static byte[] delimited(Frame... frames) throws IOException {
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (Frame frame : frames) {
            frame.writeDelimitedTo(out);
        }
        return out.toByteArray();
    }

    private static Frame hello() {
        return Frame.newBuilder().setHello(StreamHello.newBuilder().setProtocolVersion(1).setProxyInstanceId("i")).build();
    }

    private static Frame capture(long id) {
        return Frame.newBuilder().setCapture(Capture.newBuilder().setCaptureId(id)).build();
    }

    @Test
    void readsConsecutiveDelimitedFrames() throws IOException {
        final InputStream in = new ByteArrayInputStream(delimited(hello(), capture(1), capture(2)));
        final FrameDecoder decoder = new FrameDecoder(MAX);
        assertEquals(hello(), decoder.read(in).orElseThrow());
        assertEquals(1, decoder.read(in).orElseThrow().getCapture().getCaptureId());
        assertEquals(2, decoder.read(in).orElseThrow().getCapture().getCaptureId());
        assertTrue(decoder.read(in).isEmpty());
    }

    @Test
    void returnsEmptyOnCleanEofAtBoundary() throws IOException {
        assertTrue(new FrameDecoder(MAX).read(new ByteArrayInputStream(new byte[0])).isEmpty());
    }

    @Test
    void readsAnEmptyFrame() throws IOException {
        final InputStream in = new ByteArrayInputStream(new byte[] {0});
        assertEquals(Frame.getDefaultInstance(), new FrameDecoder(MAX).read(in).orElseThrow());
    }

    @Test
    void throwsOnTruncatedFrame() throws IOException {
        final byte[] whole = delimited(capture(7));
        final InputStream in = new ByteArrayInputStream(Arrays.copyOf(whole, whole.length - 1));
        assertThrows(EOFException.class, () -> new FrameDecoder(MAX).read(in));
    }

    @Test
    void throwsOnTruncatedLength() {
        final InputStream in = new ByteArrayInputStream(new byte[] {(byte) 0x80});
        assertThrows(EOFException.class, () -> new FrameDecoder(MAX).read(in));
    }

    @Test
    void rejectsDeclaredLengthAboveLimitWithoutAllocating() {
        // Declares 2^62 bytes, then nothing: reading the payload would fail or exhaust memory.
        final byte[] huge = {(byte) 0x80, (byte) 0x80, (byte) 0x80, (byte) 0x80, (byte) 0x80,
                             (byte) 0x80, (byte) 0x80, (byte) 0x80, 0x40};
        final InputStream in = new ByteArrayInputStream(huge);
        final var e = assertThrows(FrameDecoder.FrameTooLargeException.class, () -> new FrameDecoder(MAX).read(in));
        assertTrue(e.getMessage().contains("exceeds 1024"), e.getMessage());
    }

    @Test
    void acceptsALengthExactlyAtTheLimit() throws IOException {
        final Frame frame = capture(3);
        final InputStream in = new ByteArrayInputStream(delimited(frame));
        assertEquals(frame, new FrameDecoder(frame.getSerializedSize()).read(in).orElseThrow());
    }

    @Test
    void rejectsMalformedVarint() {
        final byte[] endless = new byte[11];
        Arrays.fill(endless, (byte) 0xff);
        assertThrows(IOException.class, () -> new FrameDecoder(MAX).read(new ByteArrayInputStream(endless)));
    }

    @Test
    void rejectsAPayloadThatIsNotAFrame() {
        final InputStream in = new ByteArrayInputStream(new byte[] {2, (byte) 0xff, (byte) 0xff});
        assertThrows(InvalidProtocolBufferException.class, () -> new FrameDecoder(MAX).read(in));
    }

    @Test
    void rejectsANonPositiveLimit() {
        assertThrows(IllegalArgumentException.class, () -> new FrameDecoder(0));
    }
}
