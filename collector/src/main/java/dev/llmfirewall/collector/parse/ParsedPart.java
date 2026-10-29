package dev.llmfirewall.collector.parse;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.List;

/**
 * One structural piece of a body, before labeling. Held in memory only.
 *
 * @param kind      what the part is. It decides which of the nullable fields is set.
 * @param location  a stable, content-free locator such as {@code req} or {@code resp}.
 *                  It never contains a filename or any value.
 * @param mediaType the declared media type, lower-cased without parameters
 * @param json      set when kind == JSON
 * @param text      set when kind == TEXT
 * @param sseEvents set when kind == SSE_STREAM (possibly empty)
 */
public record ParsedPart(Kind kind,
                         String location,
                         String mediaType,
                         JsonNode json,
                         String text,
                         List<SseStreamParser.SseEvent> sseEvents) {

    /** BINARY_SKIPPED marks a body of a type that is not parsed; it carries no content. */
    public enum Kind { JSON, TEXT, SSE_STREAM, BINARY_SKIPPED }
}
