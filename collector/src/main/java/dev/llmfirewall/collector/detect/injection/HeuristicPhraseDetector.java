package dev.llmfirewall.collector.detect.injection;

import com.google.re2j.Matcher;
import com.google.re2j.Pattern;
import dev.llmfirewall.collector.detect.Detection;
import dev.llmfirewall.collector.detect.Detector;
import dev.llmfirewall.collector.detect.FindingCategory;
import dev.llmfirewall.collector.label.Segment;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * RE2/J phrase rules over {@link FoldedText}, so width, case and invisible-character
 * tricks do not hide a phrase; offsets point into the original text. Rule families
 * (subtype {@code phrase:<family>}):
 * <ul>
 *   <li>{@code ignore_previous}: ignore/disregard/forget ... previous/above/system instructions</li>
 *   <li>{@code role_override}: "you are now a ...", "from now on you will", "new system
 *       prompt", "act as an unrestricted ...", "enable developer mode"</li>
 *   <li>{@code fake_boundary}: {@code <system>} or {@code </instructions>} tags, chat-template
 *       markers ({@code <|im_start|>}, {@code [INST]}), and "Human:"/"Assistant:" at the
 *       start of a line</li>
 *   <li>{@code tool_coercion}: call/execute/invoke the X tool; send/upload/post ... to a
 *       URL or address</li>
 *   <li>{@code secrecy}: do not tell/inform the user, without telling the user, keep
 *       this secret from the user</li>
 *   <li>{@code exfil_instruction}: include/append/embed ... in a URL, link, image or query string</li>
 * </ul>
 * The rules are heuristics and match benign text too (documentation about prompt
 * injection, for example). Phrasing that is ordinary in Claude's own tool use, such
 * as "use the Read tool" or {@code <system-reminder>} tags, is left out. The score is 1.0.
 */
public final class HeuristicPhraseDetector implements Detector {

    public static final String NAME = "phrase-heuristics";
    public static final int VERSION = 1;

    private static final Map<String, Pattern> RULES = new LinkedHashMap<>();

    static {
        rule("ignore_previous", "\\b(?:ignore|disregard|forget|override)\\s+(?:(?:all|any|the|your|of)\\s+)*"
                                + "(?:previous|prior|above|earlier|preceding|original|system)\\s+"
                                + "(?:instructions?|prompts?|messages|rules|directions|guidelines)\\b");
        rule("role_override", "\\byou\\s+are\\s+now\\s+(?:a|an|the|my|in)\\b"
                              + "|\\bfrom\\s+now\\s+on,?\\s+you\\s+(?:are|will|must)\\b"
                              + "|\\bnew\\s+system\\s+prompt\\b"
                              + "|\\bact\\s+as\\s+(?:a|an)\\s+(?:unrestricted|unfiltered|jailbroken|uncensored)\\b"
                              + "|\\b(?:enable|enter|activate)\\s+(?:developer|dan|god)\\s+mode\\b");
        rule("fake_boundary", "</?\\s*(?:system|instructions?|system_prompt)\\s*>"
                              + "|<\\|im_(?:start|end)\\|>|\\[/?inst\\]"
                              + "|(?:^|\\n)[ \\t]*(?:human|assistant)[ \\t]*:");
        rule("tool_coercion", "\\b(?:call|execute|invoke)\\s+the\\s+[\\w.-]+\\s+tool\\b"
                              + "|\\b(?:send|upload|post|forward|exfiltrate)\\b[^.\\n]{0,60}?\\bto\\s+"
                              + "(?:https?://|this\\s+url\\b|the\\s+following\\s+url\\b|[\\w.+-]+@[\\w-]+\\.)");
        // A straight or curly apostrophe in "don't".
        final String dont = "(?:do\\s+not|don['\\x{2019}]?t|never)";
        rule("secrecy", "\\b" + dont + "\\s+(?:tell|inform|notify|alert)\\s+the\\s+user\\b"
                        + "|\\b" + dont + "\\s+(?:mention|reveal|disclose)\\s+(?:this|it|that)\\s+to\\s+the\\s+user\\b"
                        + "|\\bwithout\\s+(?:telling|informing|notifying|alerting)\\s+the\\s+user\\b"
                        + "|\\bkeep\\s+(?:this|it)\\s+(?:secret|hidden)\\s+from\\s+the\\s+user\\b");
        rule("exfil_instruction", "\\b(?:include|append|embed|encode|insert)\\b[^.\\n]{0,80}?\\b(?:in|into|to)\\s+"
                                  + "(?:the\\s+|a\\s+|an\\s+)?"
                                  + "(?:url|link|image\\s+url|markdown\\s+image|query\\s+(?:string|parameter))\\b");
    }

    private static void rule(String family, String regex) {
        RULES.put("phrase:" + family, Pattern.compile(regex));
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
        final FoldedText folded = FoldedText.of(segment.text());
        final List<Detection> out = new ArrayList<>();
        for (Map.Entry<String, Pattern> rule : RULES.entrySet()) {
            final Matcher m = rule.getValue().matcher(folded.text());
            while (m.find()) {
                final int[] span = folded.originalSpan(m.start(), m.end());
                out.add(new Detection(NAME, VERSION, FindingCategory.INJECTION, rule.getKey(), segment,
                                      span[0], span[1], 1.0));
            }
        }
        return out;
    }
}
