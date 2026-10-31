package ca.yorku.triagedesk.domain;

/** Severity of a finding or case, ordered from least to most severe. */
public enum Severity {
    LOW(1), MEDIUM(2), HIGH(3), CRITICAL(4);

    private final int weight;

    Severity(int weight) {
        this.weight = weight;
    }

    /** Numeric weight used when computing case priority. */
    public int weight() {
        return weight;
    }

    public static Severity max(Severity a, Severity b) {
        return a.compareTo(b) >= 0 ? a : b;
    }

    /** Maps a Wazuh rule level (0-15) to a severity. */
    public static Severity fromWazuhLevel(int level) {
        if (level >= 12) return CRITICAL;
        if (level >= 10) return HIGH;
        if (level >= 7) return MEDIUM;
        return LOW;
    }
}
