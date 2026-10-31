package ca.yorku.triagedesk.domain;

import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * One normalised log line or alert. Every parser produces these, whatever the source format.
 * Fields that a format does not provide are null (ruleLevel is 0). {@code category} is a
 * format-independent event type that detectors rely on; {@code attributes} keeps
 * format-specific details such as the HTTP status or the sudo command.
 */
public record SecurityEvent(
        String id,
        String batchId,
        Instant timestamp,
        String source,
        String host,
        String user,
        String srcIp,
        String message,
        String ruleId,
        int ruleLevel,
        List<String> mitreIds,
        String category,
        Map<String, String> attributes) {

    public static final String AUTH_FAILURE = "auth_failure";
    public static final String AUTH_SUCCESS = "auth_success";
    public static final String PRIVILEGE = "privilege";
    public static final String WEB_REQUEST = "web_request";
    public static final String ALERT = "alert";
    public static final String OTHER = "other";

    public SecurityEvent {
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(batchId, "batchId");
        Objects.requireNonNull(timestamp, "timestamp");
        message = message == null ? "" : message;
        mitreIds = mitreIds == null ? List.of() : List.copyOf(mitreIds);
        category = category == null ? OTHER : category;
        Map<String, String> copy = new LinkedHashMap<>();
        if (attributes != null) {
            attributes.forEach((k, v) -> {
                if (k != null && v != null) {
                    copy.put(k, v);
                }
            });
        }
        attributes = Collections.unmodifiableMap(copy);
    }

    /** Returns a format-specific attribute, or null if the event does not have it. */
    public String attribute(String key) {
        return attributes.get(key);
    }

    public static Builder builder(String id, String batchId, Instant timestamp) {
        return new Builder(id, batchId, timestamp);
    }

    /** Builder used by the parsers, since most formats only fill some of the fields. */
    public static final class Builder {
        private final String id;
        private final String batchId;
        private final Instant timestamp;
        private String source;
        private String host;
        private String user;
        private String srcIp;
        private String message;
        private String ruleId;
        private int ruleLevel;
        private List<String> mitreIds;
        private String category;
        private final Map<String, String> attributes = new LinkedHashMap<>();

        private Builder(String id, String batchId, Instant timestamp) {
            this.id = id;
            this.batchId = batchId;
            this.timestamp = timestamp;
        }

        public Builder source(String source) { this.source = source; return this; }
        public Builder host(String host) { this.host = host; return this; }
        public Builder user(String user) { this.user = user; return this; }
        public Builder srcIp(String srcIp) { this.srcIp = srcIp; return this; }
        public Builder message(String message) { this.message = message; return this; }
        public Builder ruleId(String ruleId) { this.ruleId = ruleId; return this; }
        public Builder ruleLevel(int ruleLevel) { this.ruleLevel = ruleLevel; return this; }
        public Builder mitreIds(List<String> mitreIds) { this.mitreIds = mitreIds; return this; }
        public Builder category(String category) { this.category = category; return this; }

        public Builder attribute(String key, String value) {
            if (value != null) {
                attributes.put(key, value);
            }
            return this;
        }

        public SecurityEvent build() {
            return new SecurityEvent(id, batchId, timestamp, source, host, user, srcIp, message,
                    ruleId, ruleLevel, mitreIds, category, attributes);
        }
    }
}
