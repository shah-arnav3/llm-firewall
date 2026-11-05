package dev.llmfirewall.collector.detect.pii;

/**
 * Luhn mod-10 check. Spaces and dashes are ignored; any other non-digit fails. It
 * requires 13 to 19 digits, the lengths of payment card numbers.
 */
public final class LuhnValidator implements PiiPattern.Validator {

    @Override
    public boolean isValid(CharSequence value) {
        int digits = 0;
        int sum = 0;
        // From the rightmost digit, double every second one.
        for (int i = value.length() - 1; i >= 0; i--) {
            final char c = value.charAt(i);
            if (c == ' ' || c == '-') {
                continue;
            }
            if (c < '0' || c > '9') {
                return false;
            }
            int d = c - '0';
            if (digits % 2 == 1) {
                d *= 2;
                if (d > 9) {
                    d -= 9;
                }
            }
            sum += d;
            digits++;
        }
        return digits >= 13 && digits <= 19 && sum % 10 == 0;
    }
}
