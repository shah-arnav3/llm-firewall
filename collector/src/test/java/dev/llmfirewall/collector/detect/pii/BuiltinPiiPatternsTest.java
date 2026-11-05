package dev.llmfirewall.collector.detect.pii;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import dev.llmfirewall.collector.label.Direction;
import dev.llmfirewall.collector.label.Segment;
import dev.llmfirewall.collector.label.Source;
import java.util.List;
import org.junit.jupiter.api.Test;

class BuiltinPiiPatternsTest {

    private static final RegexPiiDetector ALL = new RegexPiiDetector(BuiltinPiiPatterns.select(BuiltinPiiPatterns.allNames()));

    /** "subtype=matched text" for each hit in {@code text}. */
    private static List<String> hits(String text) {
        final Segment s = new Segment(Source.USER_TYPED, Direction.OUTBOUND, text, "req:$.prompt");
        return ALL.detect(s).stream().map(d -> d.subtype() + "=" + text.substring(d.start(), d.end())).toList();
    }

    @Test
    void listsTheCatalogInOrder() {
        assertEquals(List.of("email", "phone", "us_ssn", "credit_card"), BuiltinPiiPatterns.allNames());
    }

    @Test
    void selectRejectsAnUnknownName() {
        assertThrows(IllegalArgumentException.class, () -> BuiltinPiiPatterns.select(List.of("email", "nope")));
    }

    @Test
    void detectsEmail() {
        assertEquals(List.of("email=jane.doe+work@mail.example.co.uk"),
                     hits("write to jane.doe+work@mail.example.co.uk."));
        assertEquals(List.of(), hits("not an address: a@b, @handle"));
    }

    @Test
    void detectsPhoneInE164AndNanpForms() {
        assertEquals(List.of("phone=+442079460958"), hits("call +442079460958 now"));
        assertEquals(List.of("phone=+44 20 7946 0958"), hits("call +44 20 7946 0958"));
        assertEquals(List.of("phone=(555) 234-5678", "phone=555.234.5678"),
                     hits("(555) 234-5678 or 555.234.5678"));
    }

    @Test
    void phoneIgnoresDigitsInsideLongerNumbers() {
        assertEquals(List.of(), hits("order 95552345678 and v1.555.234.56789"));
        assertEquals(List.of(), hits("area code 155 234 5678"));
    }

    @Test
    void detectsValidSsnAndRejectsReservedAreas() {
        assertEquals(List.of("us_ssn=123-45-6789", "us_ssn=078 05 1120"), hits("123-45-6789 and 078 05 1120"));
        assertEquals(List.of(), hits("000-12-3456 666-12-3456 900-12-3456 123-00-4567 123-45-0000"));
    }

    @Test
    void creditCardRequiresLuhn() {
        assertEquals(List.of("credit_card=4111 1111 1111 1111"), hits("card 4111 1111 1111 1111 exp"));
        assertEquals(List.of("credit_card=5555-5555-5555-4444"), hits("5555-5555-5555-4444"));
        assertEquals(List.of(), hits("4111 1111 1111 1112"));
        assertEquals(List.of("credit_card=378282246310005", "credit_card=3782 822463 10005"),
                     hits("378282246310005 or 3782 822463 10005"));
    }

    @Test
    void creditCardIgnoresRunsOfShortNumbers() {
        // 18 digits that pass Luhn, but not in a card layout.
        assertEquals(List.of(), hits("000-12-3456 666-12-3456"));
    }
}
