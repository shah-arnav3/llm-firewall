package dev.llmfirewall.collector.label;

import dev.llmfirewall.collector.coverage.CoverageCounters;
import dev.llmfirewall.collector.coverage.CoverageMetric;
import dev.llmfirewall.collector.label.adapters.AnthropicMessagesAdapter;
import dev.llmfirewall.collector.label.adapters.ClaudeAiCompletionAdapter;
import dev.llmfirewall.collector.label.adapters.ClaudeAiTitleAdapter;
import dev.llmfirewall.collector.label.adapters.FallbackAdapter;
import dev.llmfirewall.collector.parse.ParsedBody;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;

/**
 * The Label stage for one exchange: picks the adapter for its routed endpoint, labels the
 * request and the response, and records coverage.
 * <ul>
 *   <li>{@code messages_api}: {@link AnthropicMessagesAdapter}; {@code completion}:
 *       {@link ClaudeAiCompletionAdapter}; {@code title} and {@code generate_title}:
 *       {@link ClaudeAiTitleAdapter}.</li>
 *   <li>An unrouted endpoint is labeled by {@link FallbackAdapter}, all UNKNOWN, and
 *       counted as UNKNOWN_ENDPOINT[{@code host method template}] when it carried any text.</li>
 *   <li>Each field outside the adapter's schema counts as SCHEMA_DRIFT[{@code adapter part:path}],
 *       for example {@code anthropic.messages@1 req:$.new_field}.</li>
 *   <li>An adapter that throws counts as ADAPTER_FAILURE[{@code adapter}], and the
 *       fallback labels the whole exchange instead, so its text is still scanned.</li>
 * </ul>
 * Thread-safe.
 */
public final class Labeler {

    static final String FALLBACK_ID = "fallback@1";

    private final AnthropicMessagesAdapter messages;
    private final ClaudeAiCompletionAdapter completion;
    private final ClaudeAiTitleAdapter titles = new ClaudeAiTitleAdapter();
    private final FallbackAdapter fallback = new FallbackAdapter();
    private final CoverageCounters coverage;

    public Labeler(AnthropicMessagesAdapter messages, CoverageCounters coverage) {
        this.messages = messages;
        this.completion = new ClaudeAiCompletionAdapter(messages);
        this.coverage = coverage;
    }

    public LabeledExchange label(EndpointKey endpoint, ParsedBody request, ParsedBody response) {
        final String adapterId = adapterId(endpoint);
        if (adapterId.equals(FALLBACK_ID)) {
            final LabeledExchange labeled = fallback(endpoint, request, response);
            if (!labeled.result().segments().isEmpty()) {
                coverage.increment(CoverageMetric.UNKNOWN_ENDPOINT,
                                   endpoint.host() + " " + endpoint.method() + " " + endpoint.pathTemplate());
            }
            return labeled;
        }
        final LabelResult req;
        final LabelResult resp;
        try {
            req = labelRequest(endpoint.name(), request);
            resp = labelResponse(endpoint.name(), response);
        } catch (RuntimeException e) {
            coverage.increment(CoverageMetric.ADAPTER_FAILURE, adapterId);
            return fallback(endpoint, request, response);
        }
        final TreeSet<String> unknown = new TreeSet<>();
        req.unknownFieldPaths().forEach(path -> unknown.add(side("req", path)));
        resp.unknownFieldPaths().forEach(path -> unknown.add(side("resp", path)));
        for (String path : unknown) {
            coverage.increment(CoverageMetric.SCHEMA_DRIFT, adapterId + " " + path);
        }
        final List<Segment> segments = new ArrayList<>(req.segments());
        segments.addAll(resp.segments());
        final Optional<String> model = req.attributes().model().isPresent() ? req.attributes().model()
                                                                             : resp.attributes().model();
        return new LabeledExchange(endpoint, adapterId, new LabelResult(List.copyOf(segments), Set.copyOf(unknown),
            new LabelResult.Attributes(model, req.attributes().hasToolResults())));
    }

    /** Adapters report JSON paths without their side; a non-JSON part's path already names its part. */
    private static String side(String part, String path) {
        return path.startsWith("$") || path.startsWith("sse:") ? part + ":" + path : path;
    }

    private static String adapterId(EndpointKey endpoint) {
        return switch (endpoint.known() ? endpoint.name() : "") {
            case "messages_api" -> AnthropicMessagesAdapter.ID + "@" + AnthropicMessagesAdapter.VERSION;
            case "completion" -> ClaudeAiCompletionAdapter.ID + "@" + ClaudeAiCompletionAdapter.VERSION;
            case "title", "generate_title" -> ClaudeAiTitleAdapter.ID + "@" + ClaudeAiTitleAdapter.VERSION;
            default -> FALLBACK_ID;
        };
    }

    private LabelResult labelRequest(String endpoint, ParsedBody body) {
        return switch (endpoint) {
            case "messages_api" -> messages.labelRequest(body);
            case "completion" -> completion.labelRequest(body);
            default -> titles.labelRequest(endpoint, body);
        };
    }

    private LabelResult labelResponse(String endpoint, ParsedBody body) {
        return switch (endpoint) {
            case "messages_api" -> messages.labelResponse(body);
            case "completion" -> completion.labelResponse(body);
            default -> titles.labelResponse(endpoint, body);
        };
    }

    private LabeledExchange fallback(EndpointKey endpoint, ParsedBody request, ParsedBody response) {
        final List<Segment> segments = new ArrayList<>(fallback.segments(request, Direction.OUTBOUND));
        segments.addAll(fallback.segments(response, Direction.INBOUND));
        return new LabeledExchange(endpoint, FALLBACK_ID, new LabelResult(List.copyOf(segments), Set.of(),
            new LabelResult.Attributes(Optional.empty(), false)));
    }
}
