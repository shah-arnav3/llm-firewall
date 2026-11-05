package dev.llmfirewall.collector.detect;

/** The three things llm-firewall looks for. */
public enum FindingCategory {
    /** Personal data or secrets leaving in an outbound segment. */
    PII,
    /** Prompt-injection indicators in untrusted content entering Claude's context. */
    INJECTION,
    /** A model reply that tries to carry data out through links or images. */
    EXFIL
}
