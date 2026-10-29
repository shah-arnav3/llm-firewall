package dev.llmfirewall.collector.parse;

import java.util.List;

/**
 * The parse result for one body.
 *
 * @param parts      in body order. Empty if the body was omitted, empty, or failed to parse.
 * @param failures   content-free failure codes such as {@code json:syntax} or {@code decode:corrupt}.
 *                   Each is also counted in coverage.
 * @param incomplete the parts do not cover the whole body: the capture or the decoded
 *                   output was truncated, or the encoded stream ended early
 */
public record ParsedBody(List<ParsedPart> parts, List<String> failures, boolean incomplete) {

    public static final ParsedBody EMPTY = new ParsedBody(List.of(), List.of(), false);
}
