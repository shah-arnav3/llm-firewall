package dev.llmfirewall.collector;

import dev.llmfirewall.collector.config.CollectorConfig;
import dev.llmfirewall.collector.config.ConfigLoader;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.util.concurrent.CountDownLatch;
import sun.misc.Signal;

/**
 * Entry point: {@code llmfw-collector [--config <path>]}. Loads the config (by default
 * {@link ConfigLoader#defaultPath()}), starts a {@link Collector}, and runs until SIGINT
 * or SIGTERM, then closes it, logging a last summary. Operational logs go to stderr,
 * one line each, with the local time and its UTC offset.
 *
 * <p>Exit codes: 0 after a clean shutdown, 2 for a bad command line or config, 3 if the
 * socket cannot be set up.
 */
public final class CollectorMain {

    static final int EXIT_OK = 0;
    static final int EXIT_CONFIG = 2;
    static final int EXIT_SOCKET = 3;

    static final Duration SUMMARY_INTERVAL = Duration.ofSeconds(60);

    private static final String USAGE = "usage: llmfw-collector [--config <path>]\n";

    private CollectorMain() {}

    public static void main(String[] args) throws InterruptedException {
        // One line per record: time, level, message.
        System.setProperty("java.util.logging.SimpleFormatter.format", "%1$tFT%1$tT.%1$tL%1$tz %4$s %5$s%6$s%n");
        Path configPath = ConfigLoader.defaultPath();
        for (int i = 0; i < args.length; i++) {
            if (args[i].equals("--help") || args[i].equals("-h")) {
                System.out.print(USAGE);
                return;
            }
            if (args[i].equals("--config") && i + 1 < args.length) {
                configPath = Path.of(args[++i]);
                continue;
            }
            fail(System.err, USAGE, EXIT_CONFIG);
        }

        final CollectorConfig config;
        try {
            config = ConfigLoader.load(configPath);
        } catch (ConfigLoader.ConfigException e) {
            fail(System.err, "configuration: " + e.getMessage() + "\n", EXIT_CONFIG);
            return;
        }
        final Collector collector = new Collector(config, Clock.systemDefaultZone(), SUMMARY_INTERVAL);
        try {
            collector.start();
        } catch (IOException e) {
            fail(System.err, "cannot listen for the proxy: " + e.getMessage() + "\n", EXIT_SOCKET);
            return;
        }
        // Handled here rather than in a shutdown hook: logging's own hook can close the
        // handlers first, and the closing summary would be lost.
        final CountDownLatch stop = new CountDownLatch(1);
        for (String name : new String[] {"INT", "TERM"}) {
            Signal.handle(new Signal(name), signal -> stop.countDown());
        }
        stop.await();
        try {
            collector.close();
        } catch (IOException e) {
            System.err.println("closing the collector: " + e.getMessage());
        }
    }

    private static void fail(PrintStream err, String message, int code) {
        err.print(message);
        System.exit(code);
    }
}
