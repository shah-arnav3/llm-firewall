package dev.llmfirewall.collector.config;

import java.nio.file.Path;

/**
 * The parts of llm-firewall.yaml the collector uses. Paths are already tilde-expanded.
 * Further sections are added as the stages that read them are built.
 */
public record CollectorConfig(Ipc ipc) {

    /** The proxy-to-collector socket: {@code socketDir/socketName}, and the largest frame accepted. */
    public record Ipc(Path socketDir, String socketName, int maxFrameBytes) {
        public Path socketPath() {
            return socketDir.resolve(socketName);
        }
    }
}
