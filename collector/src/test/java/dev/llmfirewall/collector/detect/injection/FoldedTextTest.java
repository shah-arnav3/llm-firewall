package dev.llmfirewall.collector.detect.injection;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

class FoldedTextTest {

    /** The original text behind {@code needle}'s first occurrence in the folded text. */
    private static String originalOf(String original, String needle) {
        final FoldedText f = FoldedText.of(original);
        final int at = f.text().indexOf(needle);
        final int[] span = f.originalSpan(at, at + needle.length());
        return original.substring(span[0], span[1]);
    }

    @Test
    void foldsCaseWidthAndCompatibilityForms() {
        assertEquals("ignore previous", FoldedText.of("IGNORE Previous").text());
        assertEquals("ignore", FoldedText.of("ｉｇｎｏｒｅ").text());        // Fullwidth.
        assertEquals("ignore", FoldedText.of("𝐢gnore").text()); // Mathematical bold small i.
        assertEquals("find", FoldedText.of("ﬁnd").text());            // The fi ligature.
        assertEquals("a b", FoldedText.of("a b").text());              // No-break space.
    }

    @Test
    void dropsFormatCharacters() {
        assertEquals("ignore", FoldedText.of("ig​no‍re").text());         // Zero-width space and joiner.
        assertEquals("ignore", FoldedText.of("‮ignore‬").text());          // Bidi override.
        assertEquals("ignore", FoldedText.of("ignore󠁁󠁂").text()); // Tag characters.
    }

    @Test
    void mapsMatchesBackToTheOriginal() {
        assertEquals("ｉｇｎｏｒｅ", originalOf("please ｉｇｎｏｒｅ this", "ignore"));
        assertEquals("ig​nore", originalOf("x ig​nore y", "ignore"));
        // One original code point that folds to two units maps back whole, from either unit.
        assertEquals("ﬁ", originalOf("aﬁb", "f"));
        assertEquals("ﬁ", originalOf("aﬁb", "i"));
        assertEquals("𝐢", originalOf("𝐢gnore", "i"));
    }

    @Test
    void mapsEmptySpans() {
        final FoldedText f = FoldedText.of("a​b");
        assertArrayEquals(new int[] {0, 0}, f.originalSpan(0, 0));
        assertArrayEquals(new int[] {3, 3}, f.originalSpan(2, 2));
        assertThrows(IndexOutOfBoundsException.class, () -> f.originalSpan(1, 3));
        assertEquals("", FoldedText.of("").text());
    }
}
