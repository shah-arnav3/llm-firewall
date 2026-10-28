package dev.llmfirewall.collector.ingest;

import com.google.protobuf.InvalidProtocolBufferException;
import com.sun.security.auth.module.UnixSystem;
import dev.llmfirewall.collector.coverage.CaptureGapTracker;
import dev.llmfirewall.collector.coverage.CoverageCounters;
import dev.llmfirewall.collector.coverage.CoverageMetric;
import dev.llmfirewall.proto.v1.Capture;
import dev.llmfirewall.proto.v1.Frame;
import dev.llmfirewall.proto.v1.ProxyStats;
import dev.llmfirewall.proto.v1.StreamHello;
import java.io.BufferedInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.channels.Channels;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import jdk.net.ExtendedSocketOptions;
import jdk.net.UnixDomainPrincipal;

/**
 * The Unix domain socket server, and the one-way receiving end of the proxy stream.
 * It never writes to the socket.
 *
 * <p>{@link #start()}:
 * <ol>
 *   <li>Creates {@code socketDir} with mode 0700 if it is missing. Refuses to start
 *       unless it is a directory (not a symlink) owned by this user with mode 0700.</li>
 *   <li>Removes a stale socket at the socket path (refusing anything else there),
 *       binds, and sets the socket's mode to 0600.</li>
 *   <li>Accepts connections on its own thread. A peer running as another user is
 *       closed and counted as IPC_PEER_REJECTED. A new connection replaces the current
 *       one, because a restarted proxy reconnects.</li>
 * </ol>
 *
 * <p>Each connection is read on its own thread. Its first frame must be {@code hello}
 * with protocol version {@link #PROTOCOL_VERSION}. Then each {@code capture} counts as
 * CAPTURES_RECEIVED, goes through the gap tracker under the hello's instance id, and is
 * handed to {@link Sink#capture}; each {@code stats} goes to {@link Sink#stats}. A
 * missing or unknown hello, a second hello, an empty frame, or a frame the decoder
 * rejects closes the connection and counts as IPC_PROTOCOL_ERRORS. Frames are handled
 * one at a time even while one connection replaces another, and a blocking sink
 * blocks reading, which pushes back on the proxy.
 */
public final class CaptureReceiver implements AutoCloseable {

    /** The StreamHello.protocol_version this receiver understands. */
    public static final int PROTOCOL_VERSION = 1;

    /** Where frames go. Called from one thread at a time. */
    public interface Sink {
        /** May block; {@link #close()} interrupts it. */
        void capture(Capture capture) throws InterruptedException;

        void stats(ProxyStats stats);
    }

    private static final System.Logger LOG = System.getLogger(CaptureReceiver.class.getName());
    private static final Set<PosixFilePermission> DIR_MODE = PosixFilePermissions.fromString("rwx------");
    private static final Set<PosixFilePermission> SOCKET_MODE = PosixFilePermissions.fromString("rw-------");

    private final Path socketDir;
    private final Path socketPath;
    private final FrameDecoder decoder;
    private final CaptureGapTracker gaps;
    private final CoverageCounters coverage;
    private final Sink sink;
    private final UnixSystem self = new UnixSystem();
    private final Object handling = new Object();

    private ServerSocketChannel server;
    private Thread acceptor;
    private SocketChannel current;                   // Guarded by this.
    private final Set<Thread> readers = new HashSet<>();  // Live reader threads; guarded by this.
    private volatile boolean closed;

    public CaptureReceiver(Path socketDir, String socketName, FrameDecoder decoder, CaptureGapTracker gaps,
                           CoverageCounters coverage, Sink sink) {
        this.socketDir = socketDir;
        this.socketPath = socketDir.resolve(socketName);
        this.decoder = decoder;
        this.gaps = gaps;
        this.coverage = coverage;
        this.sink = sink;
    }

    /**
     * Binds the socket and starts accepting. Call once.
     *
     * @throws IOException if the directory is not private, something other than a socket
     *     is at the socket path, or binding fails
     */
    public void start() throws IOException {
        preparePrivateDirectory();
        removeStaleSocket();
        server = ServerSocketChannel.open(StandardProtocolFamily.UNIX);
        server.bind(UnixDomainSocketAddress.of(socketPath));
        // The directory is already 0700, so no other user can reach the socket meanwhile.
        Files.setPosixFilePermissions(socketPath, SOCKET_MODE);
        acceptor = Thread.ofPlatform().name("capture-acceptor").start(this::acceptLoop);
        LOG.log(System.Logger.Level.INFO, "listening for the proxy on {0}", socketPath);
    }

    public Path socketPath() {
        return socketPath;
    }

    /**
     * Stops accepting, closes the connection, interrupts a blocked sink, waits for every
     * thread and removes the socket. If the calling thread is interrupted while waiting,
     * it stops waiting, keeps its interrupt status and still removes the socket.
     */
    @Override
    public void close() throws IOException {
        closed = true;
        if (server == null) {
            return;
        }
        server.close();
        try {
            joinAll();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        Files.deleteIfExists(socketPath);
    }

    private void joinAll() throws InterruptedException {
        acceptor.join();
        final List<Thread> live;
        synchronized (this) {
            if (current != null) {
                closeQuietly(current);
            }
            live = new ArrayList<>(readers);
        }
        for (Thread thread : live) {
            thread.interrupt();
            thread.join();
        }
    }

    private void preparePrivateDirectory() throws IOException {
        if (!Files.exists(socketDir, LinkOption.NOFOLLOW_LINKS)) {
            Files.createDirectories(socketDir, PosixFilePermissions.asFileAttribute(DIR_MODE));
            // createDirectories applies the umask, so set the mode explicitly.
            Files.setPosixFilePermissions(socketDir, DIR_MODE);
        }
        final PosixFileAttributes attrs = Files.readAttributes(socketDir, PosixFileAttributes.class,
                                                               LinkOption.NOFOLLOW_LINKS);
        final int owner = (Integer) Files.getAttribute(socketDir, "unix:uid", LinkOption.NOFOLLOW_LINKS);
        if (!attrs.isDirectory() || owner != self.getUid() || !attrs.permissions().equals(DIR_MODE)) {
            throw new IOException(socketDir + " must be a directory owned by " + self.getUsername()
                                  + " with mode 0700");
        }
    }

    private void removeStaleSocket() throws IOException {
        if (!Files.exists(socketPath, LinkOption.NOFOLLOW_LINKS)) {
            return;
        }
        final PosixFileAttributes attrs = Files.readAttributes(socketPath, PosixFileAttributes.class,
                                                               LinkOption.NOFOLLOW_LINKS);
        // A socket is neither a regular file, a directory nor a symlink.
        if (!attrs.isOther()) {
            throw new IOException(socketPath + " exists and is not a socket");
        }
        Files.delete(socketPath);
    }

    private void acceptLoop() {
        while (!closed) {
            final SocketChannel channel;
            try {
                channel = server.accept();
            } catch (IOException e) {
                if (!closed) {
                    LOG.log(System.Logger.Level.ERROR, "accepting a proxy connection failed", e);
                }
                return;
            }
            if (!fromThisUser(channel)) {
                coverage.increment(CoverageMetric.IPC_PEER_REJECTED);
                closeQuietly(channel);
                continue;
            }
            replaceConnection(channel);
        }
    }

    private boolean fromThisUser(SocketChannel channel) {
        try {
            final UnixDomainPrincipal peer = channel.getOption(ExtendedSocketOptions.SO_PEERCRED);
            return peer.user().getName().equals(self.getUsername());
        } catch (IOException | UnsupportedOperationException e) {
            return false;
        }
    }

    private synchronized void replaceConnection(SocketChannel channel) {
        if (closed) {
            closeQuietly(channel);
            return;
        }
        if (current != null) {
            closeQuietly(current);
        }
        current = channel;
        final Thread thread = Thread.ofPlatform().name("capture-reader").unstarted(() -> {
            read(channel);
            synchronized (this) {
                readers.remove(Thread.currentThread());
            }
        });
        readers.add(thread);
        thread.start();
    }

    private void read(SocketChannel channel) {
        try (InputStream in = new BufferedInputStream(Channels.newInputStream(channel))) {
            final Optional<Frame> first = decoder.read(in);
            if (first.isEmpty()) {
                return;
            }
            final Optional<String> instanceId = acceptHello(first.get());
            if (instanceId.isEmpty()) {
                coverage.increment(CoverageMetric.IPC_PROTOCOL_ERRORS);
                return;
            }
            LOG.log(System.Logger.Level.INFO, "proxy {0} connected", instanceId.get());
            for (Optional<Frame> frame = decoder.read(in); frame.isPresent(); frame = decoder.read(in)) {
                if (!handle(instanceId.get(), frame.get())) {
                    coverage.increment(CoverageMetric.IPC_PROTOCOL_ERRORS);
                    return;
                }
            }
        } catch (FrameDecoder.FrameTooLargeException | InvalidProtocolBufferException | EOFException e) {
            if (!isCurrent(channel)) {
                return;  // Closed by us mid-frame: replaced or shutting down.
            }
            coverage.increment(CoverageMetric.IPC_PROTOCOL_ERRORS);
            LOG.log(System.Logger.Level.WARNING, "closing the proxy connection: {0}", e.getMessage());
        } catch (IOException e) {
            // Closed by us (replaced or shutting down), or the connection was reset.
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } finally {
            closeQuietly(channel);
        }
    }

    private synchronized boolean isCurrent(SocketChannel channel) {
        return !closed && current == channel;
    }

    private static Optional<String> acceptHello(Frame frame) {
        if (!frame.hasHello()) {
            LOG.log(System.Logger.Level.WARNING, "closing the proxy connection: the first frame is not hello");
            return Optional.empty();
        }
        final StreamHello hello = frame.getHello();
        if (hello.getProtocolVersion() != PROTOCOL_VERSION) {
            LOG.log(System.Logger.Level.WARNING, "closing the proxy connection: unknown protocol version {0}",
                    hello.getProtocolVersion());
            return Optional.empty();
        }
        return Optional.of(hello.getProxyInstanceId());
    }

    /** @return false if the frame breaks the protocol */
    private boolean handle(String instanceId, Frame frame) throws InterruptedException {
        synchronized (handling) {
            switch (frame.getKindCase()) {
                case CAPTURE -> {
                    coverage.increment(CoverageMetric.CAPTURES_RECEIVED);
                    gaps.observe(instanceId, frame.getCapture().getCaptureId());
                    sink.capture(frame.getCapture());
                    return true;
                }
                case STATS -> {
                    sink.stats(frame.getStats());
                    return true;
                }
                default -> {
                    return false;  // A second hello, or an empty frame.
                }
            }
        }
    }

    private static void closeQuietly(SocketChannel channel) {
        try {
            channel.close();
        } catch (IOException ignored) {
            // Nothing more to do with a channel that will not close.
        }
    }
}
