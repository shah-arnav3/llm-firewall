package dev.llmfirewall.collector.detect;

import dev.llmfirewall.collector.coverage.CoverageCounters;
import dev.llmfirewall.collector.coverage.CoverageMetric;
import dev.llmfirewall.collector.label.Direction;
import dev.llmfirewall.collector.label.LabeledExchange;
import dev.llmfirewall.collector.label.Segment;
import dev.llmfirewall.collector.label.Source;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * The Detect stage. For each segment of a labeled exchange:
 * <ol>
 *   <li>Select detector categories from the routing matrix in {@link Source}:
 *       <ul>
 *         <li>PII for OUTBOUND segments of every source except MODEL_OUTPUT;</li>
 *         <li>INJECTION for ATTACHMENT, TOOL_RESULT, SERVER_TOOL_RESULT and UNKNOWN,
 *             never USER_TYPED;</li>
 *         <li>EXFIL for INBOUND MODEL_OUTPUT.</li>
 *       </ul>
 *       Outbound MODEL_OUTPUT (earlier assistant turns that a client re-sends) gets no
 *       detector: it was scanned when it arrived.</li>
 *   <li>Run each detector of those categories. A detector that throws is counted as
 *       DETECTOR_FAILURE[name], contributes nothing for that segment, and does not
 *       affect the others.</li>
 *   <li>Merge overlapping detections of the same detector and subtype into one that
 *       spans them all and keeps the maximum score.</li>
 * </ol>
 * Thread-safe if the detectors are.
 */
public final class DetectionEngine {

    private static final System.Logger LOG = System.getLogger(DetectionEngine.class.getName());

    private final Map<FindingCategory, List<Detector>> detectors = new LinkedHashMap<>();
    private final CoverageCounters coverage;

    public DetectionEngine(List<Detector> piiDetectors,
                           List<Detector> injectionDetectors,
                           List<Detector> exfilDetectors,
                           CoverageCounters coverage) {
        detectors.put(FindingCategory.PII, List.copyOf(piiDetectors));
        detectors.put(FindingCategory.INJECTION, List.copyOf(injectionDetectors));
        detectors.put(FindingCategory.EXFIL, List.copyOf(exfilDetectors));
        this.coverage = coverage;
    }

    /** @return merged detections, grouped by segment in exchange order, each group ordered by start */
    public List<Detection> detect(LabeledExchange exchange) {
        final List<Detection> out = new ArrayList<>();
        for (Segment segment : exchange.result().segments()) {
            final List<Detection> found = new ArrayList<>();
            for (FindingCategory category : categories(segment)) {
                for (Detector detector : detectors.get(category)) {
                    found.addAll(run(detector, segment));
                }
            }
            out.addAll(merge(found));
        }
        return out;
    }

    /** The routing matrix. */
    static Set<FindingCategory> categories(Segment segment) {
        final Set<FindingCategory> out = EnumSet.noneOf(FindingCategory.class);
        final Source source = segment.source();
        if (source == Source.MODEL_OUTPUT) {
            if (segment.direction() == Direction.INBOUND) {
                out.add(FindingCategory.EXFIL);
            }
            return out;
        }
        if (segment.direction() == Direction.OUTBOUND) {
            out.add(FindingCategory.PII);
        }
        if (source != Source.USER_TYPED) {
            out.add(FindingCategory.INJECTION);
        }
        return out;
    }

    private List<Detection> run(Detector detector, Segment segment) {
        try {
            return detector.detect(segment);
        } catch (RuntimeException e) {
            coverage.increment(CoverageMetric.DETECTOR_FAILURE, detector.name());
            // The exception class only: a message could quote segment text.
            LOG.log(System.Logger.Level.WARNING, "detector {0} failed on {1}: {2}",
                    detector.name(), segment.location(), e.getClass().getName());
            return List.of();
        }
    }

    private static List<Detection> merge(List<Detection> found) {
        final List<Detection> sorted = new ArrayList<>(found);
        sorted.sort(Comparator.comparingInt(Detection::start).thenComparingInt(Detection::end));
        // Keyed by detector and subtype; each list holds that pair's merged spans.
        final Map<String, List<Detection>> spans = new LinkedHashMap<>();
        for (Detection d : sorted) {
            final List<Detection> same = spans.computeIfAbsent(d.detector() + "\0" + d.subtype(), k -> new ArrayList<>());
            final Detection last = same.isEmpty() ? null : same.get(same.size() - 1);
            if (last != null && d.start() < last.end()) {
                same.set(same.size() - 1, new Detection(last.detector(), last.detectorVersion(), last.category(),
                                                        last.subtype(), last.segment(), last.start(),
                                                        Math.max(last.end(), d.end()),
                                                        Math.max(last.score(), d.score())));
            } else {
                same.add(d);
            }
        }
        final List<Detection> out = new ArrayList<>();
        spans.values().forEach(out::addAll);
        out.sort(Comparator.comparingInt(Detection::start).thenComparingInt(Detection::end));
        return out;
    }
}
