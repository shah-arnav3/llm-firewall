package dev.llmfirewall.collector.detect;

import dev.llmfirewall.collector.label.Segment;

/**
 * An in-memory detector hit. It refers to the matched text by offsets into
 * {@code segment.text()} and never copies it, so it must not be persisted: only the
 * masked finding derived from it is stored.
 *
 * @param subtype e.g. {@code email}, {@code aws_access_key_id}, {@code PERSON},
 *                {@code phrase:ignore_previous}, {@code unicode_tags}, {@code prompt_guard},
 *                {@code md_image_query}
 * @param start   inclusive UTF-16 offset
 * @param end     exclusive UTF-16 offset
 * @param score   1.0 for deterministic detectors, otherwise the model probability
 */
public record Detection(String detector,
                        int detectorVersion,
                        FindingCategory category,
                        String subtype,
                        Segment segment,
                        int start,
                        int end,
                        double score) {}
