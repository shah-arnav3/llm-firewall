package dev.llmfirewall.collector.label;

/**
 * Output of the Label stage for one exchange.
 *
 * @param adapterId {@code id@version} of the adapter that labeled it, or {@code fallback@1}
 * @param result    request segments first, then response segments; unknown paths from both,
 *                  each prefixed with its part ({@code req:} or {@code resp:})
 */
public record LabeledExchange(EndpointKey endpoint, String adapterId, LabelResult result) {}
