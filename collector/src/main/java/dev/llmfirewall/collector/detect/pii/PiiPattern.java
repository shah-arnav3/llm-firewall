package dev.llmfirewall.collector.detect.pii;

import com.google.re2j.Pattern;

import java.util.Optional;

/**
 * One regex detector.
 *
 * @param name      the subtype stored on findings (e.g. {@code email}, {@code github_token}, or a custom name)
 * @param pattern   RE2/J (linear time, no backreferences), so user patterns cannot cause catastrophic backtracking
 * @param validator an extra check on the matched value (e.g. Luhn). Empty means "accept every match".
 * @param group     the capture group that holds the sensitive value (0 means the whole match).
 *                  A match in which the group did not participate is ignored.
 */
public record PiiPattern(String name, Pattern pattern, Optional<Validator> validator, int group) {

    /** @throws IllegalArgumentException if {@code group} is not a group of {@code pattern} */
    public PiiPattern {
        if (group < 0 || group > pattern.groupCount()) {
            throw new IllegalArgumentException(name + ": pattern has no group " + group);
        }
    }

    @FunctionalInterface
    public interface Validator {
        boolean isValid(CharSequence value);
    }
}
