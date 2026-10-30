package dev.llmfirewall.collector.label;

import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * What an adapter extracted from one body.
 *
 * @param segments          all text found, labeled. Strings in unrecognized fields are included as UNKNOWN.
 * @param unknownFieldPaths JSON key paths (no values, indices as {@code []}) not in the adapter's schema
 * @param attributes        metadata for event classification
 */
public record LabelResult(List<Segment> segments, Set<String> unknownFieldPaths, Attributes attributes) {

    /**
     * Safe-to-store metadata. It contains no content.
     *
     * @param model          model id from the request or the reply
     * @param hasToolResults the request carried TOOL_RESULT segments
     */
    public record Attributes(Optional<String> model, boolean hasToolResults) {}
}
