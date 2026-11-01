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
 * @param file      set when the part is an uploaded file, whether its text was read (TEXT) or not (BINARY_SKIPPED)
 */
public record ParsedPart(Kind kind,
                         String location,
                         String mediaType,
                         JsonNode json,
                         String text,
                         List<SseStreamParser.SseEvent> sseEvents,
                         FileInfo file) {

    /** BINARY_SKIPPED marks a body of a type that is not parsed; it carries no content. */
    public enum Kind { JSON, TEXT, SSE_STREAM, BINARY_SKIPPED }

    /** A part that is not an uploaded file. */
    public ParsedPart(Kind kind, String location, String mediaType, JsonNode json, String text,
                      List<SseStreamParser.SseEvent> sseEvents) {
        this(kind, location, mediaType, json, text, sseEvents, null);
    }

    /**
     * File metadata that is safe to keep. The original filename is deliberately absent,
     * because filenames often contain names and other personal details.
     *
     * @param fileType  the filename's lower-cased extension (letters and digits, at most 10),
     *                  or the part's media type if there is none, or {@code unknown}
     * @param sizeBytes the bytes captured for the file
     */
    public record FileInfo(String fileType, long sizeBytes) {}
}
