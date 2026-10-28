package dev.llmfirewall.collector.ingest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.llmfirewall.collector.coverage.CaptureGapTracker;
import dev.llmfirewall.collector.coverage.CoverageCounters;
import dev.llmfirewall.collector.coverage.CoverageMetric;
import dev.llmfirewall.proto.v1.Capture;
import dev.llmfirewall.proto.v1.Frame;
import dev.llmfirewall.proto.v1.ProxyStats;
import dev.llmfirewall.proto.v1.StreamHello;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.UnixDomainSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Clock;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class CaptureReceiverTest {

    private static final int MAX_FRAME = 4096;

    private Path tmp;
    private Path socketDir;
    private final CoverageCounters coverage = new CoverageCounters(10, Clock.systemDefaultZone());
    private final BlockingQueue<Object> received = new LinkedBlockingQueue<>();
    private CaptureReceiver receiver;

    /** Records every frame; a capture with id 99 blocks until the receiver closes. */
    private final CaptureReceiver.Sink sink = new CaptureReceiver.Sink() {
        @Override
        public void capture(Capture capture) throws InterruptedException {
            received.add(capture);
            if (capture.getCaptureId() == 99) {
                new CountDownLatch(1).await();
            }
        }

        @Override
        public void stats(ProxyStats stats) {
            received.add(stats);
        }
    };

    @BeforeEach
    void setUp() throws IOException {
        // Under /tmp, because a socket path is limited to 104 bytes.
        tmp = Files.createTempDirectory(Path.of("/tmp"), "llmfw-rcv");
        socketDir = tmp.resolve("run");
    }

    @AfterEach
    void tearDown() throws Exception {
        if (receiver != null) {
            receiver.close();
        }
        try (Stream<Path> paths = Files.walk(tmp)) {
            for (Path p : paths.sorted(Comparator.reverseOrder()).toList()) {
                Files.deleteIfExists(p);
            }
        }
    }

    private CaptureReceiver started() throws IOException {
        receiver = new CaptureReceiver(socketDir, "c.sock", new FrameDecoder(MAX_FRAME), new CaptureGapTracker(coverage),
                                       coverage, sink);
        receiver.start();
        return receiver;
    }

    private SocketChannel connect() throws IOException {
        return SocketChannel.open(UnixDomainSocketAddress.of(receiver.socketPath()));
    }

    private static void send(SocketChannel channel, Frame... frames) throws IOException {
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (Frame frame : frames) {
            frame.writeDelimitedTo(out);
        }
        final ByteBuffer buffer = ByteBuffer.wrap(out.toByteArray());
        while (buffer.hasRemaining()) {
            channel.write(buffer);
        }
    }

    private static Frame hello(int version, String instance) {
        return Frame.newBuilder()
            .setHello(StreamHello.newBuilder().setProtocolVersion(version).setProxyInstanceId(instance))
            .build();
    }

    private static Frame capture(long id) {
        return Frame.newBuilder().setCapture(Capture.newBuilder().setCaptureId(id)).build();
    }

    private static Frame stats(long accepted) {
        return Frame.newBuilder().setStats(ProxyStats.newBuilder().setConnectionsAccepted(accepted)).build();
    }

    private Object next() throws InterruptedException {
        final Object item = received.poll(2, TimeUnit.SECONDS);
        assertNotNull(item, "nothing received within 2 s");
        return item;
    }

    /** Whether the receiver closes `channel` within 2 s. */
    private static boolean closedByPeer(SocketChannel channel) throws Exception {
        return CompletableFuture.supplyAsync(() -> {
            try {
                return channel.read(ByteBuffer.allocate(1)) < 0;
            } catch (IOException e) {
                return true;
            }
        }).get(2, TimeUnit.SECONDS);
    }

    private Map<CoverageMetric, Long> counts() {
        final Map<CoverageMetric, Long> out = new HashMap<>();
        coverage.drain().forEach(d -> out.merge(d.metric(), d.delta(), Long::sum));
        return out;
    }

    @Test
    void createsAPrivateDirectoryAndASocketWithMode0600() throws IOException {
        started();
        assertEquals("rwx------", PosixFilePermissions.toString(Files.getPosixFilePermissions(socketDir)));
        assertEquals("rw-------", PosixFilePermissions.toString(
            Files.getPosixFilePermissions(receiver.socketPath(), LinkOption.NOFOLLOW_LINKS)));
    }

    @Test
    void refusesASocketDirWithTheWrongMode() throws IOException {
        Files.createDirectory(socketDir, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwxr-x---")));
        assertThrows(IOException.class, this::started);
    }

    @Test
    void refusesASymlinkedSocketDir() throws IOException {
        final Path real = Files.createDirectory(tmp.resolve("real"));
        Files.setPosixFilePermissions(real, PosixFilePermissions.fromString("rwx------"));
        Files.createSymbolicLink(socketDir, real);
        assertThrows(IOException.class, this::started);
    }

    @Test
    void refusesToReplaceAFileThatIsNotASocket() throws IOException {
        Files.createDirectory(socketDir, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
        Files.writeString(socketDir.resolve("c.sock"), "not a socket");
        assertThrows(IOException.class, this::started);
    }

    @Test
    void replacesAStaleSocket() throws Exception {
        started().close();
        receiver = null;
        // A crashed collector leaves its socket file behind; simulate one.
        try (var stale = java.nio.channels.ServerSocketChannel.open(java.net.StandardProtocolFamily.UNIX)) {
            stale.bind(UnixDomainSocketAddress.of(socketDir.resolve("c.sock")));
        }
        assertTrue(Files.exists(socketDir.resolve("c.sock"), LinkOption.NOFOLLOW_LINKS));
        started();
        try (SocketChannel proxy = connect()) {
            send(proxy, hello(1, "a"), capture(1));
            assertEquals(1, ((Capture) next()).getCaptureId());
        }
    }

    @Test
    void deliversCapturesAndStatsAfterHello() throws Exception {
        started();
        try (SocketChannel proxy = connect()) {
            send(proxy, hello(1, "a"), stats(4), capture(1), capture(2));
            assertEquals(4, ((ProxyStats) next()).getConnectionsAccepted());
            assertEquals(1, ((Capture) next()).getCaptureId());
            assertEquals(2, ((Capture) next()).getCaptureId());
        }
        assertEquals(Map.of(CoverageMetric.CAPTURES_RECEIVED, 2L), counts());
    }

    @Test
    void tracksCaptureIdGaps() throws Exception {
        started();
        try (SocketChannel proxy = connect()) {
            send(proxy, hello(1, "a"), capture(1), capture(4));
            next();
            next();
        }
        assertEquals(2L, counts().get(CoverageMetric.CAPTURE_ID_GAP));
    }

    @Test
    void closesTheConnectionWhenTheFirstFrameIsNotHello() throws Exception {
        started();
        try (SocketChannel proxy = connect()) {
            send(proxy, capture(1));
            assertTrue(closedByPeer(proxy));
        }
        assertNull(received.poll());
        assertEquals(Map.of(CoverageMetric.IPC_PROTOCOL_ERRORS, 1L), counts());
    }

    @Test
    void closesTheConnectionOnAnUnknownProtocolVersion() throws Exception {
        started();
        try (SocketChannel proxy = connect()) {
            send(proxy, hello(2, "a"), capture(1));
            assertTrue(closedByPeer(proxy));
        }
        assertNull(received.poll());
        assertEquals(Map.of(CoverageMetric.IPC_PROTOCOL_ERRORS, 1L), counts());
    }

    @Test
    void closesTheConnectionOnASecondHello() throws Exception {
        started();
        try (SocketChannel proxy = connect()) {
            send(proxy, hello(1, "a"), hello(1, "a"), capture(1));
            assertTrue(closedByPeer(proxy));
        }
        assertNull(received.poll());
        assertEquals(1L, counts().get(CoverageMetric.IPC_PROTOCOL_ERRORS));
    }

    @Test
    void closesTheConnectionOnAnOversizedFrame() throws Exception {
        started();
        try (SocketChannel proxy = connect()) {
            send(proxy, hello(1, "a"));
            send(proxy, Frame.newBuilder().setCapture(Capture.newBuilder()
                .setWebsocket(dev.llmfirewall.proto.v1.WebSocketMessage.newBuilder()
                    .setPayload(com.google.protobuf.ByteString.copyFrom(new byte[MAX_FRAME])))).build());
            assertTrue(closedByPeer(proxy));
        }
        assertEquals(1L, counts().get(CoverageMetric.IPC_PROTOCOL_ERRORS));
    }

    @Test
    void aNewConnectionReplacesThePreviousOne() throws Exception {
        started();
        try (SocketChannel first = connect()) {
            send(first, hello(1, "a"), capture(1));
            assertEquals(1, ((Capture) next()).getCaptureId());
            final SocketChannel second = connect();
            send(second, hello(1, "b"), capture(1));
            assertTrue(closedByPeer(first));
            assertEquals(1, ((Capture) next()).getCaptureId());
            second.close();
        }
        assertFalse(counts().containsKey(CoverageMetric.IPC_PROTOCOL_ERRORS));
    }

    @Test
    void closeInterruptsABlockedSinkAndRemovesTheSocket() throws Exception {
        started();
        try (SocketChannel proxy = connect()) {
            send(proxy, hello(1, "a"), capture(99));
            assertEquals(99, ((Capture) next()).getCaptureId());
            final long start = System.nanoTime();
            receiver.close();
            assertTrue(System.nanoTime() - start < TimeUnit.SECONDS.toNanos(2));
        }
        assertFalse(Files.exists(socketDir.resolve("c.sock"), LinkOption.NOFOLLOW_LINKS));
        receiver = null;
    }
}
