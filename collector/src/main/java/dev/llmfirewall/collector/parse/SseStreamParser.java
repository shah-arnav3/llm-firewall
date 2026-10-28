package dev.llmfirewall.collector.parse;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Splits a whole captured text/event-stream body into events, following the WHATWG
 * EventSource parsing rules:
 * <ul>
 *   <li>the body is UTF-8 (a leading BOM is dropped, invalid bytes become U+FFFD), and
 *       CRLF, LF and CR all end a line;</li>
 *   <li>a line starting with {@code :} is a comment; otherwise it is {@code field:value},
 *       with one space after the colon removed, or a bare field name with an empty value;</li>
 *   <li>{@code data} lines are joined with "\n"; {@code event} sets the type (default
 *       {@code message}); {@code id} sets the last event id, which carries over to later
 *       events, and is ignored if it contains NUL; other fields are ignored;</li>
 *   <li>a blank line ends an event, which is emitted unless it has no data.</li>
 * </ul>
 * Unlike a browser, which drops it, an event still open when the body ends (a truncated
 * capture or an aborted stream) is emitted with {@code complete=false} if it has any data.
 */
public final class SseStreamParser {

    /** One event. {@code index} is its 0-based position among the emitted events. */
    public record SseEvent(int index, String event, String data, String id, boolean complete) {}

    private static final String DEFAULT_EVENT = "message";

    public List<SseEvent> events(byte[] decoded) {
        String text = new String(decoded, StandardCharsets.UTF_8);
        if (text.startsWith("﻿")) {
            text = text.substring(1);
        }
        final List<SseEvent> events = new ArrayList<>();
        final StringBuilder data = new StringBuilder();
        String type = null;
        String lastId = "";
        boolean hasData = false;
        int pos = 0;
        while (pos < text.length()) {
            int end = pos;
            while (end < text.length() && text.charAt(end) != '\n' && text.charAt(end) != '\r') {
                end++;
            }
            final String line = text.substring(pos, end);
            final boolean terminated = end < text.length();
            pos = end + (end + 1 < text.length() && text.charAt(end) == '\r' && text.charAt(end + 1) == '\n' ? 2 : 1);
            if (line.isEmpty() && terminated) {
                if (hasData) {
                    events.add(new SseEvent(events.size(), type == null ? DEFAULT_EVENT : type, trimLastNewline(data),
                                            lastId, true));
                }
                data.setLength(0);
                type = null;
                hasData = false;
                continue;
            }
            if (line.startsWith(":")) {
                continue;
            }
            final int colon = line.indexOf(':');
            final String field = colon < 0 ? line : line.substring(0, colon);
            String value = colon < 0 ? "" : line.substring(colon + 1);
            if (value.startsWith(" ")) {
                value = value.substring(1);
            }
            switch (field) {
                case "data" -> {
                    data.append(value).append('\n');
                    hasData = true;
                }
                case "event" -> type = value;
                case "id" -> {
                    if (value.indexOf('\0') < 0) {
                        lastId = value;
                    }
                }
                default -> {
                    // "retry" and unknown fields carry nothing to record.
                }
            }
        }
        if (hasData) {
            events.add(new SseEvent(events.size(), type == null ? DEFAULT_EVENT : type, trimLastNewline(data), lastId,
                                    false));
        }
        return events;
    }

    private static String trimLastNewline(StringBuilder data) {
        return data.length() > 0 ? data.substring(0, data.length() - 1) : "";
    }
}
