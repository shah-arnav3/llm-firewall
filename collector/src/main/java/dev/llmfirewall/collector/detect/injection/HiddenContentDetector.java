package dev.llmfirewall.collector.detect.injection;

import dev.llmfirewall.collector.detect.Detection;
import dev.llmfirewall.collector.detect.Detector;
import dev.llmfirewall.collector.detect.FindingCategory;
import dev.llmfirewall.collector.label.Segment;

import java.util.ArrayList;
import java.util.List;

/**
 * Content a human reviewer would not see or could not read, but a model reads. Each
 * maximal run of one kind is one detection, spanning the run. Subtypes:
 * <ul>
 *   <li>{@code unicode_tags}: U+E0000–U+E007F, which can spell out a whole instruction
 *       invisibly;</li>
 *   <li>{@code zero_width}: U+200B–U+200D, U+2060 and U+FEFF, in runs of at least
 *       {@link #MIN_ZERO_WIDTH_RUN}. A single one is ordinary (an emoji joiner, a word-break
 *       hint, a leading byte-order mark), while data hidden in zero-width characters takes
 *       long runs. A single one splitting a phrase is still caught: {@link FoldedText}
 *       drops it before the phrase rules run;</li>
 *   <li>{@code bidi_control}: the embedding, override and isolate controls U+202A–U+202E
 *       and U+2066–U+2069, which can make text display in a different order from the one
 *       the model reads;</li>
 *   <li>{@code encoded_blob}: base64, base64url, hex or percent-encoded runs that decode
 *       to readable text of at least {@code minEncodedBlobChars} bytes; see
 *       {@link EncodedBlobScanner};</li>
 *   <li>{@code html_hidden}: HTML elements styled or marked not to display, and comments,
 *       holding text; see {@link HtmlHiddenScanner}.</li>
 * </ul>
 * The score is 1.0.
 */
public final class HiddenContentDetector implements Detector {

    public static final String NAME = "hidden-content";
    public static final int VERSION = 3;
    static final int MIN_ZERO_WIDTH_RUN = 2;

    private enum Kind {
        UNICODE_TAGS("unicode_tags", 1),
        ZERO_WIDTH("zero_width", MIN_ZERO_WIDTH_RUN),
        BIDI_CONTROL("bidi_control", 1);

        final String subtype;
        final int minRun;

        Kind(String subtype, int minRun) {
            this.subtype = subtype;
            this.minRun = minRun;
        }
    }

    private final EncodedBlobScanner blobs;
    private final HtmlHiddenScanner html = new HtmlHiddenScanner();

    /** @throws IllegalArgumentException if {@code minEncodedBlobChars} is less than 1 */
    public HiddenContentDetector(int minEncodedBlobChars) {
        this.blobs = new EncodedBlobScanner(minEncodedBlobChars);
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
        return FindingCategory.INJECTION;
    }

    @Override
    public List<Detection> detect(Segment segment) {
        final String text = segment.text();
        final List<Detection> out = new ArrayList<>();
        Kind run = null;
        int runStart = 0;
        int runLength = 0;
        for (int i = 0; i <= text.length(); ) {
            final int cp = i < text.length() ? text.codePointAt(i) : -1;
            final Kind kind = cp < 0 ? null : kindOf(cp);
            if (kind != run) {
                if (run != null && runLength >= run.minRun) {
                    out.add(new Detection(NAME, VERSION, FindingCategory.INJECTION, run.subtype, segment, runStart, i, 1.0));
                }
                run = kind;
                runStart = i;
                runLength = 0;
            }
            runLength++;
            i += cp < 0 ? 1 : Character.charCount(cp);
        }
        for (int[] span : blobs.find(text)) {
            out.add(new Detection(NAME, VERSION, FindingCategory.INJECTION, "encoded_blob", segment, span[0], span[1], 1.0));
        }
        for (int[] span : html.find(text)) {
            out.add(new Detection(NAME, VERSION, FindingCategory.INJECTION, "html_hidden", segment, span[0], span[1], 1.0));
        }
        return out;
    }

    private static Kind kindOf(int cp) {
        if (cp >= 0xE0000 && cp <= 0xE007F) {
            return Kind.UNICODE_TAGS;
        }
        if ((cp >= 0x200B && cp <= 0x200D) || cp == 0x2060 || cp == 0xFEFF) {
            return Kind.ZERO_WIDTH;
        }
        if ((cp >= 0x202A && cp <= 0x202E) || (cp >= 0x2066 && cp <= 0x2069)) {
            return Kind.BIDI_CONTROL;
        }
        return null;
    }
}
