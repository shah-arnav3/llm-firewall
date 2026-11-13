package dev.llmfirewall.collector.detect.exfil;

import com.google.re2j.Matcher;
import com.google.re2j.Pattern;
import dev.llmfirewall.collector.detect.Detection;
import dev.llmfirewall.collector.detect.Detector;
import dev.llmfirewall.collector.detect.FindingCategory;
import dev.llmfirewall.collector.label.Segment;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Finds links in model output that could send data to a third party, where the
 * {@link LinkTarget} is not on an allowlisted domain or its subdomains and
 * {@linkplain LinkTarget#carriesData carries data}. Subtypes, each spanning the URL:
 * <ul>
 *   <li>{@code md_image_query}: an inline markdown image, or a reference definition that
 *       an image uses. The most severe case, since a client loads images without a click;</li>
 *   <li>{@code md_link_query}: an inline markdown link, or any other reference definition;</li>
 *   <li>{@code autolink_query}: a bare or {@code <...>} http(s) URL outside those, including
 *       the outer link of a linked image {@code [![alt](image)](link)}.</li>
 * </ul>
 * The score is 1.0.
 */
public final class ExfilLinkDetector implements Detector {

    public static final String NAME = "exfil-links";
    public static final int VERSION = 1;

    private static final Pattern INLINE = Pattern.compile("(!?)\\[[^\\[\\]\\n]*\\]\\(\\s*<?([^\\s<>)]+)");
    private static final Pattern DEFINITION = Pattern.compile("(?m)^[ \\t]{0,3}\\[([^\\[\\]\\n]+)\\]:[ \\t]*<?([^\\s<>]+)");
    // Full [text][label], collapsed [label][] and shortcut [label] references.
    private static final Pattern REFERENCE = Pattern.compile("(!?)\\[([^\\[\\]\\n]*)\\](?:\\[([^\\[\\]\\n]*)\\])?");
    private static final Pattern BARE = Pattern.compile("(?i)https?://[^\\s<>()\\[\\]\"'`]+");
    private static final String TRAILING_PUNCTUATION = ".,;:!?";

    private final Set<String> allowlistedDomains;
    private final int minQueryChars;

    /**
     * @param allowlistedDomains domains whose links are never reported, with their subdomains
     * @throws IllegalArgumentException if {@code minQueryChars} is less than 1
     */
    public ExfilLinkDetector(Set<String> allowlistedDomains, int minQueryChars) {
        if (minQueryChars < 1) {
            throw new IllegalArgumentException("minQueryChars must be at least 1: " + minQueryChars);
        }
        final Set<String> domains = new HashSet<>();
        for (String d : allowlistedDomains) {
            domains.add(d.toLowerCase(Locale.ROOT).replaceAll("^\\.+|\\.+$", ""));
        }
        this.allowlistedDomains = Set.copyOf(domains);
        this.minQueryChars = minQueryChars;
    }

    @Override
    public String name() {
        return NAME;
    }

    @Override
    public int version() {
        return VERSION;
    }

    @Override
    public FindingCategory category() {
        return FindingCategory.EXFIL;
    }

    @Override
    public List<Detection> detect(Segment segment) {
        final String text = segment.text();
        final List<Detection> out = new ArrayList<>();
        final List<int[]> markdownUrls = new ArrayList<>();
        final Matcher inline = INLINE.matcher(text);
        while (inline.find()) {
            report(out, segment, inline.group(1).isEmpty() ? "md_link_query" : "md_image_query", inline.start(2), inline.end(2));
            markdownUrls.add(new int[] {inline.start(2), inline.end(2)});
        }
        final Set<String> imageLabels = imageLabels(text);
        final Matcher definition = DEFINITION.matcher(text);
        while (definition.find()) {
            final String subtype = imageLabels.contains(label(definition.group(1))) ? "md_image_query" : "md_link_query";
            report(out, segment, subtype, definition.start(2), definition.end(2));
            markdownUrls.add(new int[] {definition.start(2), definition.end(2)});
        }
        final Matcher bare = BARE.matcher(text);
        while (bare.find()) {
            int end = bare.end();
            while (end > bare.start() && TRAILING_PUNCTUATION.indexOf(text.charAt(end - 1)) >= 0) {
                end--;
            }
            final int start = bare.start();
            if (markdownUrls.stream().noneMatch(s -> start < s[1] && s[0] < bare.end())) {
                report(out, segment, "autolink_query", start, end);
            }
        }
        return out;
    }

    private void report(List<Detection> out, Segment segment, String subtype, int start, int end) {
        LinkTarget.parse(segment.text().substring(start, end))
            .filter(target -> !target.hostIn(allowlistedDomains) && target.carriesData(minQueryChars))
            .ifPresent(target -> out.add(new Detection(NAME, VERSION, FindingCategory.EXFIL, subtype, segment, start, end, 1.0)));
    }

    /** The labels that image references use, normalized. */
    private static Set<String> imageLabels(String text) {
        final Set<String> out = new HashSet<>();
        final Matcher m = REFERENCE.matcher(text);
        while (m.find()) {
            if (!m.group(1).isEmpty()) {
                out.add(label(m.group(3) == null || m.group(3).isEmpty() ? m.group(2) : m.group(3)));
            }
        }
        return out;
    }

    /** Markdown matches reference labels ignoring case and runs of whitespace. */
    private static String label(String raw) {
        return raw.strip().replaceAll("\\s+", " ").toLowerCase(Locale.ROOT);
    }
}
