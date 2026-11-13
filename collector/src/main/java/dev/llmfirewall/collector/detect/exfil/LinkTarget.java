package dev.llmfirewall.collector.detect.exfil;

import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;

/**
 * The parts of an absolute or protocol-relative http(s) URL that decide whether a link
 * can carry data off-site. The host is found the way a browser finds it: after the last
 * {@code @} of the authority, which ends at {@code /}, {@code \}, {@code ?} or {@code #}.
 * It is lower-cased, with any port and trailing dot removed.
 *
 * @param host         never empty
 * @param pathSegments the path split on {@code /}, empty segments dropped
 * @param query        the text between {@code ?} and {@code #}, empty if there is none
 */
record LinkTarget(String host, List<String> pathSegments, String query) {

    /** @return the target of {@code url}, or empty if it is not an http(s) or {@code //} URL with a host */
    static Optional<LinkTarget> parse(String url) {
        final String lower = url.toLowerCase(Locale.ROOT);
        final int authority = lower.startsWith("https://") ? 8 : lower.startsWith("http://") ? 7 : lower.startsWith("//") ? 2 : -1;
        if (authority < 0) {
            return Optional.empty();
        }
        int end = authority;
        while (end < url.length() && "/\\?#".indexOf(url.charAt(end)) < 0) {
            end++;
        }
        String host = lower.substring(Math.max(lower.lastIndexOf('@', end - 1) + 1, authority), end);
        final int port = host.lastIndexOf(':');
        if (port >= 0 && port > host.lastIndexOf(']')) {
            host = host.substring(0, port);
        }
        if (host.endsWith(".")) {
            host = host.substring(0, host.length() - 1);
        }
        if (host.isEmpty()) {
            return Optional.empty();
        }
        final int fragment = url.indexOf('#', end);
        final String rest = fragment < 0 ? url.substring(end) : url.substring(end, fragment);
        final int question = rest.indexOf('?');
        final String path = question < 0 ? rest : rest.substring(0, question);
        final String query = question < 0 ? "" : rest.substring(question + 1);
        final List<String> segments = Arrays.stream(path.replace('\\', '/').split("/")).filter(s -> !s.isEmpty()).toList();
        return Optional.of(new LinkTarget(host, segments, query));
    }

    /** Whether the host is one of {@code domains} (lower-case) or a subdomain of one. */
    boolean hostIn(Set<String> domains) {
        for (String domain : domains) {
            if (host.equals(domain) || host.endsWith("." + domain)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Whether the URL can carry at least {@code minChars} characters of data to its host:
     * in the query, not counting {@code utm_*} tracking parameters, or in one path
     * segment that looks encoded: hex digits mixing letters and digits, or base64
     * characters mixing upper case, lower case and digits, unlike a word, a slug or a
     * numeric id. A fragment never reaches the server, so it does not count.
     */
    boolean carriesData(int minChars) {
        int queryChars = 0;
        for (String parameter : query.split("&")) {
            if (!parameter.toLowerCase(Locale.ROOT).startsWith("utm_")) {
                queryChars += parameter.length();
            }
        }
        if (queryChars >= minChars) {
            return true;
        }
        return pathSegments.stream().anyMatch(s -> s.length() >= minChars && looksEncoded(s));
    }

    private static boolean looksEncoded(String segment) {
        final boolean digits = segment.chars().anyMatch(c -> c >= '0' && c <= '9');
        if (digits && segment.chars().allMatch(c -> (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))
            && !segment.chars().allMatch(c -> c >= '0' && c <= '9')) {
            return true;
        }
        final boolean base64 = segment.chars().allMatch(c -> (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z')
                                                              || (c >= 'A' && c <= 'Z') || "+=_-".indexOf(c) >= 0);
        return base64 && digits && segment.chars().anyMatch(c -> c >= 'A' && c <= 'Z')
               && segment.chars().anyMatch(c -> c >= 'a' && c <= 'z');
    }
}
