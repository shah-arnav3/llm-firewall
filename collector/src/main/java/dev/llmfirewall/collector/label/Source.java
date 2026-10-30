package dev.llmfirewall.collector.label;

/**
 * Where a piece of text came from. This decides which detectors run on it:
 *
 * <pre>
 *  Source              Wire direction   PII   Injection   Exfil
 *  USER_TYPED          outbound         yes   NO          -
 *  ATTACHMENT          outbound         yes   yes         -
 *  TOOL_RESULT         outbound         yes   yes         -
 *  SERVER_TOOL_RESULT  inbound          -     yes         -
 *  MODEL_OUTPUT        inbound          -     -           yes
 *  UNKNOWN             outbound         yes   yes         -
 *  UNKNOWN             inbound          -     yes         -
 * </pre>
 *
 * Adapters must use USER_TYPED only when they are certain the text was typed by the
 * user. When in doubt, use UNKNOWN, which is scanned for everything.
 */
public enum Source {
    /** Text the user typed into the prompt box (or the CLI prompt). It is trusted for injection purposes. */
    USER_TYPED,
    /** Uploaded files and pasted attachments, as text extracted from the upload or the request. */
    ATTACHMENT,
    /** Results of client-side tools (local MCP servers, Claude Code tools), seen in outbound requests. */
    TOOL_RESULT,
    /** Results of server-side tools (web search, connectors), seen only if present in the response stream. */
    SERVER_TOOL_RESULT,
    /** Text the model generated. */
    MODEL_OUTPUT,
    /** Strings in fields no adapter recognizes. They are still scanned. */
    UNKNOWN
}
