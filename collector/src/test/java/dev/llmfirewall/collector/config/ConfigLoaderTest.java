package dev.llmfirewall.collector.config;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ConfigLoaderTest {

    private static final Path HOME = Path.of(System.getProperty("user.home"));

    @TempDir
    Path tmp;

    private Path write(String yaml) throws IOException {
        return Files.writeString(tmp.resolve("llm-firewall.yaml"), yaml);
    }

    private String failure(String yaml) throws IOException {
        final Path file = write(yaml);
        return assertThrows(ConfigLoader.ConfigException.class, () -> ConfigLoader.load(file)).getMessage();
    }

    @Test
    void loadsTheExampleConfig() {
        final CollectorConfig cfg = ConfigLoader.load(Path.of("../config/llm-firewall.yaml"));
        assertEquals(HOME.resolve("Library/Application Support/llm-firewall/run"), cfg.ipc().socketDir());
        assertEquals("capture.sock", cfg.ipc().socketName());
        assertEquals(20 << 20, cfg.ipc().maxFrameBytes());
        assertEquals(cfg.ipc().socketDir().resolve("capture.sock"), cfg.ipc().socketPath());
    }

    @Test
    void appliesDefaults() throws IOException {
        final CollectorConfig cfg = ConfigLoader.load(write("version: 1\nipc:\n  socket_dir: /tmp/run\n"));
        assertEquals(new CollectorConfig.Ipc(Path.of("/tmp/run"), "capture.sock", 20 << 20), cfg.ipc());
    }

    @Test
    void ignoresSectionsItDoesNotUse() throws IOException {
        final CollectorConfig cfg = ConfigLoader.load(write(
            "version: 1\nproxy:\n  listen_port: 1\n  unknown: [1, 2]\nipc:\n  socket_dir: /tmp/run\n  stats_interval_ms: 5\n"));
        assertEquals(Path.of("/tmp/run"), cfg.ipc().socketDir());
    }

    @Test
    void theDefaultPathIsInApplicationSupport() {
        assertEquals(HOME.resolve("Library/Application Support/llm-firewall/llm-firewall.yaml"), ConfigLoader.defaultPath());
    }

    @Test
    void rejectsAMissingOrMalformedFile() throws IOException {
        assertThrows(ConfigLoader.ConfigException.class, () -> ConfigLoader.load(tmp.resolve("missing.yaml")));
        assertTrue(failure("version: [1\n").contains("not valid YAML"));
        assertTrue(failure("- 1\n- 2\n").contains("must be a YAML mapping"));
    }

    @Test
    void refusesArbitraryTypes() throws IOException {
        assertTrue(failure("version: 1\nipc: !!java.net.URL [\"http://example.com\"]\n").contains("not valid YAML"));
    }

    @Test
    void checksTheVersion() throws IOException {
        assertEquals("version: must be 1", failure("version: 2\nipc:\n  socket_dir: /tmp/run\n"));
        assertEquals("version: must be 1", failure("ipc:\n  socket_dir: /tmp/run\n"));
    }

    @Test
    void checksTheIpcSection() throws IOException {
        assertEquals("ipc: required, and must be a mapping", failure("version: 1\n"));
        assertEquals("ipc.socket_dir: required, and must be a string", failure("version: 1\nipc:\n  socket_name: a\n"));
        assertEquals("ipc.socket_name: must be a file name, not a path",
                     failure("version: 1\nipc:\n  socket_dir: /tmp\n  socket_name: a/b.sock\n"));
        assertTrue(failure("version: 1\nipc:\n  socket_dir: /tmp/" + "d".repeat(100) + "\n")
                       .startsWith("ipc.socket_dir: socket path is 118 bytes"));
        for (String bad : new String[] {"0", "-1", "3000000000", "\"20\""}) {
            assertEquals("ipc.max_frame_bytes: must be a positive integer below 2^31",
                         failure("version: 1\nipc:\n  socket_dir: /tmp\n  max_frame_bytes: " + bad + "\n"), bad);
        }
    }

    @Test
    void expandsATildeToTheHomeDirectory() throws IOException {
        assertEquals(HOME.resolve("run"),
                     ConfigLoader.load(write("version: 1\nipc:\n  socket_dir: \"~/run\"\n")).ipc().socketDir());
    }
}
