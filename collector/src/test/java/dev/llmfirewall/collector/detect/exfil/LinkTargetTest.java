package dev.llmfirewall.collector.detect.exfil;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.Test;

class LinkTargetTest {

    private static final Set<String> ALLOWED = Set.of("claude.ai", "github.com");

    private static LinkTarget target(String url) {
        return LinkTarget.parse(url).orElseThrow();
    }

    private static String host(String url) {
        return target(url).host();
    }

    @Test
    void parsesTheHostAsABrowserDoes() {
        assertEquals("evil.example", host("HTTPS://Evil.Example./x"));
        assertEquals("evil.example", host("http://evil.example:8080?q=1"));
        assertEquals("evil.example", host("//evil.example/pixel.png"));
        assertEquals("evil.example", host("https://claude.ai@evil.example/"));
        assertEquals("evil.example", host("https://evil.example\\@claude.ai/"));
        assertEquals("[::1]", host("http://[::1]:80/"));
    }

    @Test
    void splitsThePathAndQueryAndDropsTheFragment() {
        assertEquals(new LinkTarget("a.example", List.of("p", "q"), "x=1&y=2"), target("https://a.example/p//q?x=1&y=2#frag"));
        assertEquals(new LinkTarget("a.example", List.of(), ""), target("https://a.example"));
    }

    @Test
    void rejectsUrlsWithoutAnHttpHost() {
        for (String url : List.of("/relative/path?q=1", "mailto:a@b.example", "javascript:alert(1)", "ftp://a.example/",
                                  "https:///path", "https://user@/x")) {
            assertEquals(Optional.empty(), LinkTarget.parse(url), url);
        }
    }

    @Test
    void matchesAllowlistedDomainsAndTheirSubdomainsOnly() {
        assertTrue(target("https://claude.ai/x").hostIn(ALLOWED));
        assertTrue(target("https://gist.github.com/x").hostIn(ALLOWED));
        assertFalse(target("https://claude.ai.evil.example/x").hostIn(ALLOWED));
        assertFalse(target("https://notgithub.com/x").hostIn(ALLOWED));
    }

    @Test
    void aLongQueryCarriesData() {
        assertTrue(target("https://e.example/p?data=c2VjcmV0IHN0dWZm").carriesData(16));
        assertFalse(target("https://e.example/p?q=short").carriesData(16));
    }

    @Test
    void trackingParametersAndFragmentsDoNotCount() {
        assertFalse(target("https://e.example/p?utm_source=claude.ai&utm_medium=referral").carriesData(16));
        assertFalse(target("https://e.example/p#:~:text=a%20long%20quoted%20passage").carriesData(16));
    }

    @Test
    void anEncodedLookingPathSegmentCarriesData() {
        assertTrue(target("https://e.example/9f86d081884c7d659a2feaa0c55ad015/p.png").carriesData(16));
        assertTrue(target("https://e.example/c2VjcmV0X3Rva2VuPTEy/p.png").carriesData(16));
        assertFalse(target("https://e.example/how-to-bake-sourdough-bread").carriesData(16));
        assertFalse(target("https://e.example/status/1789012345678901234").carriesData(16));
        assertFalse(target("https://e.example/9f86d081/short").carriesData(16));
    }
}
