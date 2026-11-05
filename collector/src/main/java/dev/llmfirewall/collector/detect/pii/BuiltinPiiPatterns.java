package dev.llmfirewall.collector.detect.pii;

import com.google.re2j.Pattern;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * The built-in pattern catalog, keyed by the names in {@code detect.pii.builtin}:
 * <ul>
 *   <li>{@code email}</li>
 *   <li>{@code phone}: E.164 ({@code +} and 7 to 15 digits, optionally separated) and
 *       NANP ({@code (555) 234-5678}, {@code 555.234.5678}, ...) forms</li>
 *   <li>{@code us_ssn}: {@code AAA-GG-SSSS} with dashes or spaces. Excludes the 000, 666
 *       and 9xx area numbers and the all-zero group and serial, which are never issued.</li>
 *   <li>{@code credit_card}: card layouts (13 to 19 unbroken digits; 4-4-4-4 plus up to
 *       3 more digits; 4-6-5 or 4-6-4), separated by spaces or dashes, that pass
 *       {@link LuhnValidator}. Requiring a card layout keeps runs of short numbers,
 *       such as a list of SSNs, from reading as one long number.</li>
 * </ul>
 * RE2/J has no lookbehind, so a pattern that must not start mid-number consumes the
 * preceding character and reports the value as group 1.
 */
public final class BuiltinPiiPatterns {

    private static final Map<String, PiiPattern> CATALOG = new LinkedHashMap<>();

    static {
        add("email", "[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\\.[A-Za-z0-9-]+)*\\.[A-Za-z]{2,}\\b", null, 0);
        add("phone", "(?:^|[^\\w+])(\\+[1-9](?:[ .-]?\\d){6,14}"
                     + "|\\(?[2-9]\\d{2}\\)?[ .-]?[2-9]\\d{2}[ .-]?\\d{4})\\b", null, 1);
        add("us_ssn", "\\b(?:0(?:0[1-9]|[1-9]\\d)|[1-578]\\d\\d|6(?:[0-57-9]\\d|6[0-57-9]))"
                      + "[- ](?:0[1-9]|[1-9]\\d)[- ](?:000[1-9]|00[1-9]\\d|0[1-9]\\d\\d|[1-9]\\d{3})\\b", null, 0);
        add("credit_card", "\\b(?:\\d{13,19}|\\d{4}(?:[ -]\\d{4}){3}(?:[ -]?\\d{1,3})?|\\d{4}[ -]\\d{6}[ -]\\d{4,5})\\b",
            new LuhnValidator(), 0);
    }

    private BuiltinPiiPatterns() {}

    private static void add(String name, String regex, PiiPattern.Validator validator, int group) {
        CATALOG.put(name, new PiiPattern(name, Pattern.compile(regex), Optional.ofNullable(validator), group));
    }

    /**
     * @return the named patterns, in the order given
     * @throws IllegalArgumentException for an unknown name
     */
    public static List<PiiPattern> select(List<String> names) {
        final List<PiiPattern> out = new ArrayList<>();
        for (String name : names) {
            final PiiPattern p = CATALOG.get(name);
            if (p == null) {
                throw new IllegalArgumentException("unknown built-in PII pattern: " + name);
            }
            out.add(p);
        }
        return out;
    }

    /** Every built-in name, in catalog order. */
    public static List<String> allNames() {
        return List.copyOf(CATALOG.keySet());
    }
}
