package dev.llmfirewall.collector.detect.injection;

import com.google.re2j.Pattern;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.jsoup.nodes.Comment;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.nodes.Node;
import org.jsoup.parser.Parser;
import org.jsoup.select.NodeFilter;
import org.jsoup.select.NodeTraversor;

/**
 * Finds HTML a browser would not display but a model reads as text:
 * <ul>
 *   <li>elements with the {@code hidden} attribute, or an inline style of
 *       {@code display:none}, {@code visibility:hidden} or {@code collapse}, a zero
 *       {@code font-size} or {@code opacity}, or a {@code color} equal to the
 *       {@code background} or {@code background-color};</li>
 *   <li>comments.</li>
 * </ul>
 * A hidden element or comment is reported when it holds at least
 * {@link #MIN_HIDDEN_CHARS} non-whitespace characters of text, which leaves out the
 * empty placeholders and short markers ordinary pages are full of. Inside a reported
 * element, nothing further is reported. Spans run from the start tag to the end tag,
 * or to where the parser closed an element that has none. Text that contains neither a
 * comment nor a tag with a {@code style} or {@code hidden} attribute is not parsed.
 * Thread-safe.
 */
final class HtmlHiddenScanner {

    static final int MIN_HIDDEN_CHARS = 32;

    private static final Pattern MAY_HIDE = Pattern.compile("(?i)<!--|<[a-z][^>]*\\b(?:style|hidden)\\b");
    private static final Pattern ZERO = Pattern.compile("(?:0+(?:\\.0*)?|\\.0+)(?:px|pt|em|rem|%)?");

    /** @return the {start, end} UTF-16 spans of the hidden elements and comments, in text order */
    List<int[]> find(String text) {
        if (!MAY_HIDE.matcher(text).find()) {
            return List.of();
        }
        final Document doc = Parser.htmlParser().setTrackPosition(true).parseInput(text, "");
        final List<int[]> out = new ArrayList<>();
        NodeTraversor.filter(new NodeFilter() {
            @Override
            public FilterResult head(Node node, int depth) {
                if (!node.sourceRange().isTracked()) {
                    return FilterResult.CONTINUE;
                }
                if (node instanceof Comment comment && visibleChars(comment.getData()) >= MIN_HIDDEN_CHARS) {
                    out.add(new int[] {node.sourceRange().startPos(), node.sourceRange().endPos()});
                } else if (node instanceof Element element && hidden(element)) {
                    if (visibleChars(element.text()) < MIN_HIDDEN_CHARS) {
                        return FilterResult.CONTINUE;
                    }
                    final int end = element.endSourceRange().isTracked()
                                    ? element.endSourceRange().endPos() : element.sourceRange().endPos();
                    out.add(new int[] {element.sourceRange().startPos(), end});
                    return FilterResult.SKIP_CHILDREN;
                }
                return FilterResult.CONTINUE;
            }
        }, doc);
        return out;
    }

    private static boolean hidden(Element element) {
        if (element.hasAttr("hidden")) {
            return true;
        }
        final Map<String, String> style = new HashMap<>();
        for (String declaration : element.attr("style").toLowerCase(Locale.ROOT).split(";")) {
            final int colon = declaration.indexOf(':');
            if (colon > 0) {
                style.put(declaration.substring(0, colon).strip(),
                          declaration.substring(colon + 1).replace("!important", "").strip());
            }
        }
        final String color = style.get("color");
        return "none".equals(style.get("display"))
               || "hidden".equals(style.get("visibility")) || "collapse".equals(style.get("visibility"))
               || zero(style.get("font-size")) || zero(style.get("opacity"))
               || (color != null && (color.equals(style.get("background-color")) || color.equals(style.get("background"))));
    }

    private static boolean zero(String value) {
        return value != null && ZERO.matcher(value).matches();
    }

    private static long visibleChars(String text) {
        return text.codePoints().filter(cp -> !Character.isWhitespace(cp)).count();
    }
}
