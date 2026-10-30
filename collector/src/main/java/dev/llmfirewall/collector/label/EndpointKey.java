package dev.llmfirewall.collector.label;

import java.util.Map;

/**
 * A routed endpoint.
 *
 * @param name         the route's name, e.g. {@code completion} or {@code messages_api}; empty when unknown
 * @param host         lower-cased request host
 * @param method       upper-cased HTTP method
 * @param pathTemplate e.g. {@code /api/organizations/{org}/chat_conversations/{conv}/completion}.
 *                     For unknown endpoints, the path with id-like segments replaced by {@code {id}}.
 * @param pathParams   template variables, e.g. {@code org} and {@code conv}. They are identifiers and may be stored.
 * @param known        false if no route matched
 */
public record EndpointKey(String name, String host, String method, String pathTemplate, Map<String, String> pathParams,
                          boolean known) {}
