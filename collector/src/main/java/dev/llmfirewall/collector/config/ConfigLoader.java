package dev.llmfirewall.collector.config;

import java.io.IOException;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;
import org.yaml.snakeyaml.error.YAMLException;

/**
 * Loads llm-firewall.yaml with SnakeYAML's SafeConstructor, so a file can never
 * instantiate arbitrary types. Sections and keys the collector does not use are
 * ignored, because the proxy reads the same file. It checks:
 * <ul>
 *   <li>{@code version} is 1;</li>
 *   <li>{@code ipc.socket_dir} is set; a leading {@code ~/} is the user's home;</li>
 *   <li>{@code ipc.socket_name} (default {@code capture.sock}) is a file name, not a path;</li>
 *   <li>the socket path is at most 103 bytes, the macOS limit;</li>
 *   <li>{@code ipc.max_frame_bytes} (default 20 MiB) is a positive integer that fits in an int.</li>
 * </ul>
 */
public final class ConfigLoader {

    static final int MAX_SOCKET_PATH_BYTES = 103;
    static final String DEFAULT_SOCKET_NAME = "capture.sock";
    static final int DEFAULT_MAX_FRAME_BYTES = 20 << 20;

    private ConfigLoader() {}

    /** ~/Library/Application Support/llm-firewall/llm-firewall.yaml */
    public static Path defaultPath() {
        return home().resolve("Library/Application Support/llm-firewall/llm-firewall.yaml");
    }

    /** @throws ConfigException on a missing or malformed file, or any failed check; the message names the key */
    public static CollectorConfig load(Path file) {
        final Object document;
        try (Reader reader = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
            document = new Yaml(new SafeConstructor(new LoaderOptions())).load(reader);
        } catch (IOException e) {
            throw new ConfigException(file + ": cannot read the file: " + e.getMessage());
        } catch (YAMLException e) {
            throw new ConfigException(file + ": not valid YAML: " + e.getMessage());
        }
        if (!(document instanceof Map<?, ?> root)) {
            throw new ConfigException(file + ": must be a YAML mapping");
        }
        if (!Integer.valueOf(1).equals(root.get("version"))) {
            throw new ConfigException("version: must be 1");
        }
        return new CollectorConfig(parseIpc(section(root, "ipc")));
    }

    private static CollectorConfig.Ipc parseIpc(Map<?, ?> ipc) {
        final Object dir = ipc.get("socket_dir");
        if (!(dir instanceof String rawDir) || rawDir.isEmpty()) {
            throw new ConfigException("ipc.socket_dir: required, and must be a string");
        }
        final Object name = valueOr(ipc, "socket_name", DEFAULT_SOCKET_NAME);
        if (!(name instanceof String socketName) || socketName.isEmpty() || socketName.contains("/")) {
            throw new ConfigException("ipc.socket_name: must be a file name, not a path");
        }
        final Path socketDir = expandTilde(rawDir);
        final int pathBytes = socketDir.resolve(socketName).toString().getBytes(StandardCharsets.UTF_8).length;
        if (pathBytes > MAX_SOCKET_PATH_BYTES) {
            throw new ConfigException("ipc.socket_dir: socket path is " + pathBytes + " bytes; macOS allows at most "
                                      + MAX_SOCKET_PATH_BYTES);
        }
        final Object maxFrame = valueOr(ipc, "max_frame_bytes", DEFAULT_MAX_FRAME_BYTES);
        if (!(maxFrame instanceof Integer maxFrameBytes) || maxFrameBytes <= 0) {
            throw new ConfigException("ipc.max_frame_bytes: must be a positive integer below 2^31");
        }
        return new CollectorConfig.Ipc(socketDir, socketName, maxFrameBytes);
    }

    private static Map<?, ?> section(Map<?, ?> root, String key) {
        final Object value = root.get(key);
        if (!(value instanceof Map<?, ?> map)) {
            throw new ConfigException(key + ": required, and must be a mapping");
        }
        return map;
    }

    /** The value at {@code key}, or {@code fallback} if it is missing or null. */
    private static Object valueOr(Map<?, ?> map, String key, Object fallback) {
        final Object value = map.get(key);
        return value == null ? fallback : value;
    }

    private static Path expandTilde(String raw) {
        if (raw.equals("~")) {
            return home();
        }
        return raw.startsWith("~/") ? home().resolve(raw.substring(2)) : Path.of(raw);
    }

    private static Path home() {
        return Path.of(System.getProperty("user.home"));
    }

    public static final class ConfigException extends RuntimeException {
        private static final long serialVersionUID = 1L;

        public ConfigException(String message) {
            super(message);
        }
    }
}
