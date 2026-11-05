package dev.llmfirewall.collector.detect.pii;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;

import com.google.re2j.Pattern;
import dev.llmfirewall.collector.detect.Detection;
import dev.llmfirewall.collector.detect.FindingCategory;
import dev.llmfirewall.collector.label.Direction;
import dev.llmfirewall.collector.label.Segment;
import dev.llmfirewall.collector.label.Source;
import java.time.Duration;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;

class RegexPiiDetectorTest {

    private static Segment segment(String text) {
        return new Segment(Source.USER_TYPED, Direction.OUTBOUND, text, "req:$.prompt");
    }

    private static PiiPattern pattern(String name, String regex) {
        return new PiiPattern(name, Pattern.compile(regex), Optional.empty(), 0);
    }

    /** "subtype=matched text" for each detection, in order. */
    private static List<String> hits(List<Detection> detections) {
        return detections.stream()
            .map(d -> d.subtype() + "=" + d.segment().text().substring(d.start(), d.end()))
            .toList();
    }

    @Test
    void customPatternUsesItsNameAsSubtype() {
        final Segment s = segment("ticket EMP-1234 and EMP-5678");
        final List<Detection> found = new RegexPiiDetector(List.of(pattern("employee_id", "EMP-\\d{4}"))).detect(s);
        assertEquals(List.of("employee_id=EMP-1234", "employee_id=EMP-5678"), hits(found));
        final Detection first = found.get(0);
        assertEquals(new Detection("regex-pii", 1, FindingCategory.PII, "employee_id", s, 7, 15, 1.0), first);
    }

    @Test
    void reportsOverlappingMatchesOfDifferentPatterns() {
        final RegexPiiDetector detector = new RegexPiiDetector(List.of(pattern("digits", "\\d+"), pattern("pair", "\\d\\d")));
        assertEquals(List.of("digits=123", "pair=12"), hits(detector.detect(segment("a123"))));
    }

    @Test
    void reportsOnlyTheChosenGroup() {
        final PiiPattern keyed = new PiiPattern("secret", Pattern.compile("key=(\\w+)|token"), Optional.empty(), 1);
        // "token" matches without the group, so it is not a hit.
        assertEquals(List.of("secret=abc"), hits(new RegexPiiDetector(List.of(keyed)).detect(segment("key=abc token"))));
    }

    @Test
    void dropsMatchesTheValidatorRejects() {
        final PiiPattern even = new PiiPattern("even", Pattern.compile("\\d+"),
                                               Optional.of(v -> Integer.parseInt(v.toString()) % 2 == 0), 0);
        assertEquals(List.of("even=12"), hits(new RegexPiiDetector(List.of(even)).detect(segment("11 12 13"))));
    }

    @Test
    void offsetsPointIntoSegmentText() {
        // Each emoji is two UTF-16 units, and offsets count UTF-16 units.
        final Segment s = segment("😀😀 EMP-1234");
        final Detection d = new RegexPiiDetector(List.of(pattern("employee_id", "EMP-\\d{4}"))).detect(s).get(0);
        assertEquals(5, d.start());
        assertEquals("EMP-1234", s.text().substring(d.start(), d.end()));
    }

    @Test
    void pathologicalCustomPatternRunsInLinearTime() {
        // Catastrophic for a backtracking engine: (a+)+b against a long run of a's with no b.
        final String text = "a".repeat(100_000);
        final RegexPiiDetector detector = new RegexPiiDetector(List.of(pattern("evil", "(a+)+b")));
        assertEquals(List.of(), assertTimeoutPreemptively(Duration.ofSeconds(5), () -> detector.detect(segment(text))));
    }

    @Test
    void rejectsAGroupThePatternDoesNotHave() {
        assertThrows(IllegalArgumentException.class,
                     () -> new PiiPattern("bad", Pattern.compile("a(b)"), Optional.empty(), 2));
    }
}
