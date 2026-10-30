package dev.llmfirewall.collector.label;

/**
 * A labeled unit of text. It is the input to detection and is held in memory only.
 *
 * @param source    who or what produced the text
 * @param direction network direction
 * @param text      the plaintext. It NEVER leaves the process. Only masked derivatives are persisted.
 * @param location  a content-free locator, e.g. {@code req:$.prompt},
 *                  {@code req:$.messages[3].content[1](tool_result)},
 *                  {@code resp:sse:block[2](web_search_tool_result)} or
 *                  {@code req:multipart:part[1](file)}
 */
public record Segment(Source source, Direction direction, String text, String location) {}
