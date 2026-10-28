package dev.llmfirewall.collector.coverage;

import java.time.Clock;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Thread-safe in-memory accumulators per (metric, dimension), drained periodically for
 * storage. Dimension strings must be content-free: callers pass only hosts, templates,
 * key paths, detector names, codes and proxy instance ids. Each metric keeps at most
 * {@code maxDimensionsPerMetric} distinct dimensions between drains; further ones are
 * counted under {@link #OTHER_DIMENSION}, so drift in hostile input cannot blow up storage.
 */
public final class CoverageCounters {

    /** The dimension of a counter that has none. */
    public static final String NO_DIMENSION = "";
    /** Where counts for dimensions beyond the cap go. */
    public static final String OTHER_DIMENSION = "<other>";

    /** An amount accumulated since the last drain. {@code day} is the local date of the drain. */
    public record Delta(LocalDate day, CoverageMetric metric, String dimension, long delta) {}

    private record Key(CoverageMetric metric, String dimension) {}

    private final int maxDimensionsPerMetric;
    private final Clock clock;
    private Map<Key, Long> amounts = new LinkedHashMap<>();
    private final Map<CoverageMetric, Set<String>> dimensions = new EnumMap<>(CoverageMetric.class);

    /** @throws IllegalArgumentException if {@code maxDimensionsPerMetric} is not positive */
    public CoverageCounters(int maxDimensionsPerMetric, Clock clock) {
        if (maxDimensionsPerMetric <= 0) {
            throw new IllegalArgumentException("maxDimensionsPerMetric must be positive: " + maxDimensionsPerMetric);
        }
        this.maxDimensionsPerMetric = maxDimensionsPerMetric;
        this.clock = clock;
    }

    public void increment(CoverageMetric metric) {
        add(metric, NO_DIMENSION, 1);
    }

    public void increment(CoverageMetric metric, String dimension) {
        add(metric, dimension, 1);
    }

    /** Adds {@code amount}, which may be zero but not negative. */
    public synchronized void add(CoverageMetric metric, String dimension, long amount) {
        if (amount < 0) {
            throw new IllegalArgumentException("negative amount " + amount + " for " + metric);
        }
        final Set<String> seen = dimensions.computeIfAbsent(metric, m -> new HashSet<>());
        String kept = dimension;
        if (!seen.contains(dimension)) {
            if (seen.size() < maxDimensionsPerMetric) {
                seen.add(dimension);
            } else {
                kept = OTHER_DIMENSION;
            }
        }
        amounts.merge(new Key(metric, kept), amount, Long::sum);
    }

    /** Returns and resets everything accumulated since the last drain, in first-counted order. */
    public synchronized List<Delta> drain() {
        final LocalDate today = LocalDate.now(clock);
        final List<Delta> out = new ArrayList<>(amounts.size());
        amounts.forEach((key, amount) -> out.add(new Delta(today, key.metric(), key.dimension(), amount)));
        amounts = new LinkedHashMap<>();
        dimensions.clear();
        return out;
    }
}
