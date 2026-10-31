package ca.yorku.triagedesk.domain;

import java.util.List;
import java.util.Objects;

/** The agent's proposed verdict for a case, with its reasoning and the tool calls it made. */
public record TriageVerdict(Verdict verdict, double confidence, String reasoning, List<String> toolTrace) {

    public TriageVerdict {
        Objects.requireNonNull(verdict, "verdict");
        if (Double.isNaN(confidence) || confidence < 0.0 || confidence > 1.0) {
            throw new IllegalArgumentException("confidence must be between 0 and 1: " + confidence);
        }
        reasoning = reasoning == null ? "" : reasoning;
        toolTrace = toolTrace == null ? List.of() : List.copyOf(toolTrace);
    }

    /** Fallback when the model's answer is invalid or the step limit was reached. */
    public static TriageVerdict needsReview(String rawText, List<String> toolTrace) {
        return new TriageVerdict(Verdict.NEEDS_REVIEW, 0.0, rawText, toolTrace);
    }
}
