package ca.yorku.triagedesk.intel;

/** One provider's verdict on an indicator: a score from 0 (clean or unknown) to 100 (malicious) and a short explanation. */
public record IntelResult(int score, String summary) {

    public IntelResult {
        if (score < 0 || score > 100) {
            throw new IllegalArgumentException("score must be 0-100: " + score);
        }
        summary = summary == null ? "" : summary;
    }
}
