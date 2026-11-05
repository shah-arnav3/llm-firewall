package dev.llmfirewall.collector.detect.pii;

import com.google.re2j.Matcher;
import dev.llmfirewall.collector.detect.Detection;
import dev.llmfirewall.collector.detect.Detector;
import dev.llmfirewall.collector.detect.FindingCategory;
import dev.llmfirewall.collector.label.Segment;

import java.util.ArrayList;
import java.util.List;

/**
 * Runs {@link PiiPattern}s over a segment. Each pattern reports every non-overlapping
 * match whose value passes its validator; matches of different patterns may overlap.
 * The subtype is the pattern's name and the score is always 1.0.
 */
public final class RegexPiiDetector implements Detector {

    public static final String NAME = "regex-pii";
    public static final int VERSION = 1;

    private final List<PiiPattern> patterns;

    public RegexPiiDetector(List<PiiPattern> patterns) {
        this.patterns = List.copyOf(patterns);
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
        return FindingCategory.PII;
    }

    @Override
    public List<Detection> detect(Segment segment) {
        final String text = segment.text();
        final List<Detection> out = new ArrayList<>();
        for (PiiPattern p : patterns) {
            final Matcher m = p.pattern().matcher(text);
            while (m.find()) {
                final int start = m.start(p.group());
                if (start < 0) {
                    continue;
                }
                final int end = m.end(p.group());
                if (p.validator().map(v -> v.isValid(text.subSequence(start, end))).orElse(true)) {
                    out.add(new Detection(NAME, VERSION, FindingCategory.PII, p.name(), segment, start, end, 1.0));
                }
            }
        }
        return out;
    }
}
