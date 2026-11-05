package dev.llmfirewall.collector.detect.pii;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class LuhnValidatorTest {

    private final LuhnValidator luhn = new LuhnValidator();

    @Test
    void acceptsValidNumbersWithOrWithoutSeparators() {
        assertTrue(luhn.isValid("4111111111111111"));
        assertTrue(luhn.isValid("4111 1111 1111 1111"));
        assertTrue(luhn.isValid("3782-822463-10005"));  // 15-digit Amex test number.
    }

    @Test
    void rejectsAWrongCheckDigit() {
        assertFalse(luhn.isValid("4111111111111112"));
    }

    @Test
    void rejectsLengthsOutsideThirteenToNineteen() {
        assertFalse(luhn.isValid("000000000000"));       // 12 digits, sum 0.
        assertTrue(luhn.isValid("0000000000000"));       // 13.
        assertTrue(luhn.isValid("0000000000000000000")); // 19.
        assertFalse(luhn.isValid("00000000000000000000"));
    }

    @Test
    void rejectsOtherCharacters() {
        assertFalse(luhn.isValid("4111.1111.1111.1111"));
    }
}
