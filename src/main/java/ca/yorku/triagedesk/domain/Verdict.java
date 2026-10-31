package ca.yorku.triagedesk.domain;

/** Possible outcomes of a triage. NEEDS_REVIEW is used whenever the AI output cannot be trusted. */
public enum Verdict {
    TRUE_POSITIVE, FALSE_POSITIVE, BENIGN, NEEDS_REVIEW;

    /**
     * Lenient parse of model output or user input such as "true positive", "False_Positive",
     * "tp" or "fp"; unknown text gives NEEDS_REVIEW.
     */
    public static Verdict parse(String text) {
        if (text == null) {
            return NEEDS_REVIEW;
        }
        String normalised = text.strip().toUpperCase(java.util.Locale.ROOT).replace(' ', '_').replace('-', '_');
        if (normalised.equals("TP")) {
            return TRUE_POSITIVE;
        }
        if (normalised.equals("FP")) {
            return FALSE_POSITIVE;
        }
        for (Verdict v : values()) {
            if (v.name().equals(normalised)) {
                return v;
            }
        }
        return NEEDS_REVIEW;
    }
}
