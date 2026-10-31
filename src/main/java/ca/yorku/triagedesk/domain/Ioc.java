package ca.yorku.triagedesk.domain;

import java.util.Objects;

/**
 * An indicator of compromise and its reputation score (0 to 100, higher is worse).
 * A score of {@link #UNAVAILABLE} means no provider could rate it.
 */
public record Ioc(String type, String value, int score, String source) {

    public static final String IP = "ip";
    public static final String DOMAIN = "domain";
    public static final String URL = "url";
    public static final String HASH = "hash";

    public static final int UNAVAILABLE = -1;

    public Ioc {
        Objects.requireNonNull(type, "type");
        Objects.requireNonNull(value, "value");
        if (score != UNAVAILABLE && (score < 0 || score > 100)) {
            throw new IllegalArgumentException("score must be 0-100 or UNAVAILABLE: " + score);
        }
    }

    /** A freshly extracted indicator that has not been looked up yet. */
    public static Ioc unscored(String type, String value) {
        return new Ioc(type, value, UNAVAILABLE, null);
    }

    public Ioc withScore(int newScore, String newSource) {
        return new Ioc(type, value, newScore, newSource);
    }

    public boolean isScored() {
        return score != UNAVAILABLE;
    }
}
