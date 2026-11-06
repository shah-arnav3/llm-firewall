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
        assertEquals("ignore", FoldedText.of("ｉｇｎｏｒｅ").text());                  // Fullwidth.
        assertEquals("ignore", FoldedText.of("\uD835\uDC22gnore").text());       // Mathematical bold small i.
        assertEquals("find", FoldedText.of("\uFB01nd").text());                  // The fi ligature.
        assertEquals("a b", FoldedText.of("a\u00A0b").text());                   // No-break space.
    }

    @Test
    void dropsFormatCharacters() {
        assertEquals("ignore", FoldedText.of("ig\u200Bno\u200Dre").text());      // Zero-width space and joiner.
        assertEquals("ignore", FoldedText.of("\u202Eignore\u202C").text());      // Bidi override.
        assertEquals("ignore", FoldedText.of("ignore\uDB40\uDC41\uDB40\uDC42").text()); // Tag characters.
    }

    @Test
    void mapsMatchesBackToTheOriginal() {
        assertEquals("ｉｇｎｏｒｅ", originalOf("please ｉｇｎｏｒｅ this", "ignore"));
        assertEquals("ig\u200Bnore", originalOf("x ig\u200Bnore y", "ignore"));
        // One original code point that folds to two units maps back whole, from either unit.
        assertEquals("\uFB01", originalOf("a\uFB01b", "f"));
        assertEquals("\uFB01", originalOf("a\uFB01b", "i"));
        assertEquals("\uD835\uDC22", originalOf("\uD835\uDC22gnore", "i"));
    }

    @Test
    void mapsEmptySpans() {
        final FoldedText f = FoldedText.of("a\u200Bb");
        assertArrayEquals(new int[] {0, 0}, f.originalSpan(0, 0));
        assertArrayEquals(new int[] {3, 3}, f.originalSpan(2, 2));
        assertThrows(IndexOutOfBoundsException.class, () -> f.originalSpan(1, 3));
        assertEquals("", FoldedText.of("").text());
    }
}
