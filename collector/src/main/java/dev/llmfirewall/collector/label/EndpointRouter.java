package dev.llmfirewall.collector.label;

import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Maps (host, method, target) to an {@link EndpointKey} with a static route table of
 * the endpoints seen carrying conversation content:
 * <pre>
 *  POST claude.ai         /api/organizations/{org}/chat_conversations/{conv}/completion  completion
 *  POST claude.ai         /api/organizations/{org}/chat_conversations/{conv}/title       title
 *  POST claude.ai         /api/organizations/{org}/dust/generate_title_and_branch        generate_title
 *  POST api.anthropic.com /v1/messages                                                   messages_api
 * </pre>
 * The query string is ignored, hosts and methods ignore case, and a {@code {var}} matches
 * exactly one non-empty segment. Anything else is unknown, with a template that replaces
 * id-like segments ({@link #ID_LIKE}) with {@code {id}}, so the template can be counted
 * by without collecting one entry per conversation. Opaque tokens without digits, such
 * as an SDK key, are kept; they are identifiers, not content. Thread-safe.
 */
public final class EndpointRouter {

    private record Route(String name, String host, String method, String[] segments) {}

    private static final List<Route> ROUTES = List.of(
        route("completion", "claude.ai", "POST", "/api/organizations/{org}/chat_conversations/{conv}/completion"),
        route("title", "claude.ai", "POST", "/api/organizations/{org}/chat_conversations/{conv}/title"),
        route("generate_title", "claude.ai", "POST", "/api/organizations/{org}/dust/generate_title_and_branch"),
        route("messages_api", "api.anthropic.com", "POST", "/v1/messages"));

    /** A number, a UUID, 16 or more hex digits, or any segment of 8 or more characters with at least two digits. */
    private static final Pattern ID_LIKE = Pattern.compile(
        "[0-9]+|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|[0-9a-fA-F]{16,}"
        + "|(?=.{8,})(?=.*[0-9].*[0-9]).*");

    /** Whether a path segment or key looks like an identifier ({@link #ID_LIKE}) rather than a word. */
    public static boolean isIdLike(String segment) {
        return ID_LIKE.matcher(segment).matches();
    }

    private static Route route(String name, String host, String method, String template) {
        return new Route(name, host, method, template.substring(1).split("/", -1));
    }

    public EndpointKey route(String host, String method, String target) {
        final String h = host.toLowerCase(Locale.ROOT);
        final String m = method.toUpperCase(Locale.ROOT);
        final int query = target.indexOf('?');
        final String path = query < 0 ? target : target.substring(0, query);
        final String[] segments = path.startsWith("/") ? path.substring(1).split("/", -1) : new String[] {path};
        for (Route r : ROUTES) {
            final Map<String, String> params = match(r, h, m, segments);
            if (params != null) {
                return new EndpointKey(r.name(), h, m, "/" + String.join("/", r.segments()), Map.copyOf(params), true);
            }
        }
        final StringBuilder template = new StringBuilder();
        for (String segment : segments) {
            template.append('/').append(isIdLike(segment) ? "{id}" : segment);
        }
        return new EndpointKey("", h, m, template.toString(), Map.of(), false);
    }

    private static Map<String, String> match(Route r, String host, String method, String[] segments) {
        if (!r.host().equals(host) || !r.method().equals(method) || r.segments().length != segments.length) {
            return null;
        }
        final Map<String, String> params = new HashMap<>();
        for (int i = 0; i < segments.length; i++) {
            final String want = r.segments()[i];
            if (want.startsWith("{") && want.endsWith("}")) {
                if (segments[i].isEmpty()) {
                    return null;
                }
                params.put(want.substring(1, want.length() - 1), segments[i]);
            } else if (!want.equals(segments[i])) {
                return null;
            }
        }
        return params;
    }
}
