package dev.llmfirewall.collector.detect.injection;

import java.text.Normalizer;
import java.util.Arrays;
import java.util.Locale;

/**
 * Text prepared for phrase matching, with a map from its offsets back to the original.
 * Each code point of the original is NFKC-normalized and lower-cased on its own, and
 * format characters (zero-width spaces and joiners, bidi controls, tag characters) are
 * dropped. That undoes the tricks that hide a phrase from a plain match: fullwidth or
 * mathematical letters, ligatures, odd case, and invisible characters inside words.
 * Normalizing per code point skips NFKC's canonical composition, which only matters
 * for accented letters, not for the ASCII phrases this is used with.
 */
public final class FoldedText {

    private final String original;
    private final String text;
    /** For each UTF-16 unit of {@link #text}: where its source code point starts and ends in the original. */
    private final int[] starts;
    private final int[] ends;

    private FoldedText(String original, String text, int[] starts, int[] ends) {
        this.original = original;
        this.text = text;
        this.starts = starts;
        this.ends = ends;
    }

    public static FoldedText of(String original) {
        final StringBuilder out = new StringBuilder(original.length());
        int[] starts = new int[original.length()];
        int[] ends = new int[original.length()];
        for (int i = 0; i < original.length(); ) {
            final int cp = original.codePointAt(i);
            final int next = i + Character.charCount(cp);
            if (Character.getType(cp) != Character.FORMAT) {
                final String folded = Normalizer.normalize(Character.toString(cp), Normalizer.Form.NFKC)
                    .toLowerCase(Locale.ROOT);
                if (out.length() + folded.length() > starts.length) {
                    final int size = Math.max(starts.length * 2, out.length() + folded.length());
                    starts = Arrays.copyOf(starts, size);
                    ends = Arrays.copyOf(ends, size);
                }
                for (int k = 0; k < folded.length(); k++) {
                    starts[out.length() + k] = i;
                    ends[out.length() + k] = next;
                }
                out.append(folded);
            }
            i = next;
        }
        return new FoldedText(original, out.toString(), starts, ends);
    }

    /** The folded text to match against. */
    public String text() {
        return text;
    }

    /**
     * Maps a match {@code [start, end)} in {@link #text()} back to the original. The
     * result covers every original code point that contributed to the match, plus any
     * dropped format characters between them.
     *
     * @return {@code {originalStart, originalEnd}}
     * @throws IndexOutOfBoundsException unless {@code 0 <= start <= end <= text().length()}
     */
    public int[] originalSpan(int start, int end) {
        if (start < 0 || start > end || end > text.length()) {
            throw new IndexOutOfBoundsException("[" + start + ", " + end + ") of " + text.length());
        }
        if (start == end) {
            final int at = start == text.length() ? original.length() : starts[start];
            return new int[] {at, at};
        }
        return new int[] {starts[start], ends[end - 1]};
    }
}
