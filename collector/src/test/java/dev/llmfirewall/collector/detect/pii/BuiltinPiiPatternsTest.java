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
        assertEquals(List.of("email", "phone", "us_ssn", "credit_card", "anthropic_api_key", "openai_api_key",
                             "aws_access_key_id", "aws_secret_access_key", "github_token", "slack_token",
                             "private_key_block", "jwt"),
                     BuiltinPiiPatterns.allNames());
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

    // Secret-shaped fixtures are assembled at run time so that secret scanners do not
    // flag this file.

    @Test
    void detectsAnthropicAndOpenAiKeys() {
        final String anthropic = "sk-" + "ant-api03-" + "Ab_cD-ef".repeat(4);
        final String openAiLegacy = "sk-" + "Abcdef".repeat(8);
        final String openAiProject = "sk-" + "proj-" + "Ab_cD-ef".repeat(4);
        assertEquals(List.of("anthropic_api_key=" + anthropic), hits("key: " + anthropic));
        assertEquals(List.of("openai_api_key=" + openAiLegacy, "openai_api_key=" + openAiProject),
                     hits(openAiLegacy + " " + openAiProject));
        assertEquals(List.of(), hits("risk-free task-runner sk-short"));
    }

    @Test
    void detectsAwsKeyIdAndAnchoredSecret() {
        final String keyId = "AKIA" + "ABCDEFGHIJKLMNOP";
        final String secret = "abcdEFGH/ijklMNOP+qrstUVWXyzabCDEFghijKLMN".substring(0, 40);
        assertEquals(List.of("aws_access_key_id=" + keyId), hits("id " + keyId + " ok"));
        assertEquals(List.of("aws_secret_access_key=" + secret), hits("AWS_SECRET_ACCESS_KEY=\"" + secret + "\""));
        assertEquals(List.of("aws_secret_access_key=" + secret), hits("aws_secret_key: " + secret));
        // The same 40 characters without a key name, or as part of a longer string, are not reported.
        assertEquals(List.of(), hits("hash " + secret));
        assertEquals(List.of(), hits("secret_access_key=" + secret + "XY"));
    }

    @Test
    void detectsGithubAndSlackTokens() {
        final String classic = "gh" + "p_" + "Abcdef".repeat(6);
        final String fineGrained = "github" + "_pat_" + "Ab_cdef".repeat(4);
        final String slack = "xo" + "xb-" + "1234-5678-AbCdEf";
        assertEquals(List.of("github_token=" + classic, "github_token=" + fineGrained),
                     hits(classic + " " + fineGrained));
        assertEquals(List.of("slack_token=" + slack), hits("token " + slack));
        assertEquals(List.of(), hits("gh" + "p_short xo" + "xz-1234567890"));
    }

    @Test
    void detectsPrivateKeyBlockAndJwt() {
        final String block = "-----BEGIN " + "RSA PRIVATE KEY-----\nMIIEabc\n-----END " + "RSA PRIVATE KEY-----";
        assertEquals(List.of("private_key_block=" + block), hits("key:\n" + block + "\ndone"));
        final String cutOff = "-----BEGIN " + "PRIVATE KEY-----\nMIIEabc";
        assertEquals(List.of("private_key_block=" + cutOff), hits("pasted " + cutOff));
        assertEquals(List.of(), hits("-----BEGIN PUBLIC KEY-----\nMIIBabc\n-----END PUBLIC KEY-----"));

        final String jwt = "eyJhbGciOiJIUzI1NiJ9" + ".eyJzdWIiOiJ4In0" + ".c2lnbmF0dXJl";
        final String unsigned = "eyJhbGciOiJub25lIn0" + ".eyJzdWIiOiJ4In0" + ".";
        assertEquals(List.of("jwt=" + jwt, "jwt=" + unsigned), hits("Bearer " + jwt + " or " + unsigned));
        assertEquals(List.of(), hits("eyJhbGciOiJIUzI1NiJ9.notjson.sig"));
    }
}
