package dev.llmfirewall.collector.label.adapters;

import dev.llmfirewall.collector.label.Direction;
import dev.llmfirewall.collector.label.LabelResult;
import dev.llmfirewall.collector.label.Segment;
import dev.llmfirewall.collector.label.Source;
import dev.llmfirewall.collector.parse.ParsedBody;
import dev.llmfirewall.collector.parse.ParsedPart;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;

/**
 * claude.ai {@code .../conversations/{conv}/wiggle/upload-file}: one multipart upload per
 * attached file (mapping v1). Requests:
 * <ul>
 *   <li>the text of a file part: ATTACHMENT. Files whose text could not be read (PDFs and
 *       other binary files) are skipped parts and give no segment.</li>
 *   <li>plain form fields, as text or JSON: UNKNOWN, reported as {@code part(text)} or
 *       {@code part(json)} until their meaning is known.</li>
 * </ul>
 * Replies (file ids and previews) have not been surveyed: every string in them is
 * labeled UNKNOWN, without reporting drift. Project knowledge files are seen only here,
 * at upload. Stateless and thread-safe.
 */
public final class ClaudeAiUploadAdapter {

    public static final String ID = "claude-ai.upload";
    public static final int VERSION = 1;

    public LabelResult labelRequest(ParsedBody body) {
        final List<Segment> segments = new ArrayList<>();
        final TreeSet<String> unknown = new TreeSet<>();
        final FallbackAdapter fallback = new FallbackAdapter();
        for (ParsedPart part : body.parts()) {
            if (part.kind() == ParsedPart.Kind.BINARY_SKIPPED) {
                continue;
            }
            if (part.file() != null && part.kind() == ParsedPart.Kind.TEXT) {
                if (!part.text().isEmpty()) {
                    segments.add(new Segment(Source.ATTACHMENT, Direction.OUTBOUND, part.text(), part.location()));
                }
                continue;
            }
            segments.addAll(fallback.segments(new ParsedBody(List.of(part), List.of(), false), Direction.OUTBOUND));
            unknown.add("part(" + part.kind().name().toLowerCase() + ")");
        }
        return new LabelResult(List.copyOf(segments), Set.copyOf(unknown), new LabelResult.Attributes(Optional.empty(), false));
    }

    public LabelResult labelResponse(ParsedBody body) {
        return new LabelResult(new FallbackAdapter().segments(body, Direction.INBOUND), Set.of(),
                               new LabelResult.Attributes(Optional.empty(), false));
    }
}
