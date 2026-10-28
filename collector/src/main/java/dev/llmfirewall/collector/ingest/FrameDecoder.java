package dev.llmfirewall.collector.ingest;

import dev.llmfirewall.proto.v1.Frame;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.util.Optional;

/**
 * Reads varint-length-delimited {@link Frame}s (protobuf "delimited" encoding).
 * The varint length is read and checked against {@code maxFrameBytes} before any
 * payload is allocated, so a corrupt or hostile length cannot force a huge allocation.
 * Holds no state between calls, so one decoder can serve any number of streams.
 */
public final class FrameDecoder {

    /** A varint carries 7 bits per byte, so a 64-bit length takes at most 10 bytes. */
    private static final int MAX_VARINT_BYTES = 10;

    private final int maxFrameBytes;

    /** @throws IllegalArgumentException if {@code maxFrameBytes} is not positive */
    public FrameDecoder(int maxFrameBytes) {
        if (maxFrameBytes <= 0) {
            throw new IllegalArgumentException("maxFrameBytes must be positive: " + maxFrameBytes);
        }
        this.maxFrameBytes = maxFrameBytes;
    }

    /**
     * @return the next frame, or empty on a clean EOF at a frame boundary
     * @throws FrameTooLargeException if the declared length exceeds the limit. The caller closes the connection.
     * @throws IOException on a malformed length, a truncated frame, a payload that is not
     *     a Frame ({@link com.google.protobuf.InvalidProtocolBufferException}), or an I/O error
     */
    public Optional<Frame> read(InputStream in) throws IOException {
        final int first = in.read();
        if (first < 0) {
            return Optional.empty();
        }
        final long length = readLength(first, in);
        if (length > maxFrameBytes) {
            throw new FrameTooLargeException(length, maxFrameBytes);
        }
        final byte[] payload = in.readNBytes((int) length);
        if (payload.length < length) {
            throw new EOFException("truncated frame: " + payload.length + " of " + length + " bytes");
        }
        return Optional.of(Frame.parseFrom(payload));
    }

    /** Reads the rest of a varint whose first byte is {@code first}. */
    private static long readLength(int first, InputStream in) throws IOException {
        long value = 0;
        int b = first;
        for (int i = 0; i < MAX_VARINT_BYTES; i++) {
            if (i > 0) {
                b = in.read();
                if (b < 0) {
                    throw new EOFException("truncated frame length");
                }
            }
            value |= (long) (b & 0x7f) << (7 * i);
            if ((b & 0x80) == 0) {
                if (value < 0) {
                    throw new IOException("malformed frame length: above 2^63");
                }
                return value;
            }
        }
        throw new IOException("malformed frame length: more than " + MAX_VARINT_BYTES + " bytes");
    }

    public static final class FrameTooLargeException extends IOException {
        private static final long serialVersionUID = 1L;

        public FrameTooLargeException(long declared, int max) {
            super("frame length " + declared + " exceeds " + max);
        }
    }
}
