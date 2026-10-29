package dev.llmfirewall.collector;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.llmfirewall.collector.config.CollectorConfig;
import dev.llmfirewall.collector.coverage.CoverageCounters.Delta;
import dev.llmfirewall.collector.coverage.CoverageMetric;
import com.google.protobuf.ByteString;
import dev.llmfirewall.proto.v1.Body;
import dev.llmfirewall.proto.v1.Capture;
import dev.llmfirewall.proto.v1.Header;
import dev.llmfirewall.proto.v1.HttpRequest;
import dev.llmfirewall.proto.v1.HttpResponse;
import dev.llmfirewall.proto.v1.Frame;
import dev.llmfirewall.proto.v1.HttpExchange;
import dev.llmfirewall.proto.v1.ProxyStats;
import dev.llmfirewall.proto.v1.StreamHello;
import dev.llmfirewall.proto.v1.TunnelSummary;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.UnixDomainSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class CollectorTest {

    private Path tmp;

    @BeforeEach
    void setUp() throws IOException {
        tmp = Files.createTempDirectory(Path.of("/tmp"), "llmfw-col");
    }

    @AfterEach
    void tearDown() throws IOException {
        try (Stream<Path> paths = Files.walk(tmp)) {
            for (Path p : paths.sorted(Comparator.reverseOrder()).toList()) {
                Files.deleteIfExists(p);
            }
        }
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

    private static Frame capture(long id, Capture.Builder payload) {
        return Frame.newBuilder().setCapture(payload.setCaptureId(id)).build();
    }

    @Test
    void countsCapturesAndRecordsCoverage() throws Exception {
        final CollectorConfig config = new CollectorConfig(new CollectorConfig.Ipc(tmp.resolve("run"), "c.sock", 1 << 20));
        try (Collector collector = new Collector(config, Clock.systemDefaultZone(), Duration.ofHours(1))) {
            collector.start();
            try (SocketChannel proxy = SocketChannel.open(UnixDomainSocketAddress.of(config.ipc().socketPath()))) {
                send(proxy,
                     Frame.newBuilder().setHello(StreamHello.newBuilder().setProtocolVersion(1).setProxyInstanceId("p")).build(),
                     Frame.newBuilder().setStats(ProxyStats.newBuilder().setProxyInstanceId("p").setCapturesDroppedQueueFull(2)).build(),
                     capture(1, Capture.newBuilder().setHttp(HttpExchange.newBuilder()
                         .setRequest(HttpRequest.newBuilder()
                             .addHeaders(Header.newBuilder().setName("Content-Type").setValue("application/json"))
                             .setBody(Body.newBuilder().setData(ByteString.copyFromUtf8("{\"a\":"))))
                         .setResponse(HttpResponse.newBuilder()
                             .addHeaders(Header.newBuilder().setName("content-type").setValue("image/png"))
                             .setBody(Body.newBuilder().setData(ByteString.copyFromUtf8("png")))))),
                     capture(2, Capture.newBuilder().setTunnel(TunnelSummary.getDefaultInstance())),
                     capture(4, Capture.newBuilder().setTunnel(TunnelSummary.getDefaultInstance())));
            }
            final long deadline = System.nanoTime() + Duration.ofSeconds(2).toNanos();
            while (collector.captureCounts().values().stream().mapToLong(Long::longValue).sum() < 3
                   && System.nanoTime() < deadline) {
                Thread.sleep(5);
            }
            assertEquals(Map.of(Capture.PayloadCase.HTTP, 1L, Capture.PayloadCase.TUNNEL, 2L), collector.captureCounts());

            final Map<String, Long> coverage = new HashMap<>();
            for (Delta d : collector.logSummary()) {
                coverage.put(d.metric() + "[" + d.dimension() + "]", d.delta());
            }
            assertEquals(Map.of(CoverageMetric.PROXY_CAPTURES_DROPPED_QUEUE_FULL + "[p]", 2L,
                                CoverageMetric.CAPTURES_RECEIVED + "[]", 3L,
                                CoverageMetric.PARSE_FAILURE + "[json:syntax]", 1L,
                                CoverageMetric.BODY_SKIPPED + "[image/png]", 1L,
                                CoverageMetric.CAPTURE_ID_GAP + "[p]", 1L),
                         coverage);
            assertTrue(collector.logSummary().isEmpty(), "a summary resets the coverage");
        }
        assertTrue(Files.notExists(config.ipc().socketPath()), "close removes the socket");
    }
}
