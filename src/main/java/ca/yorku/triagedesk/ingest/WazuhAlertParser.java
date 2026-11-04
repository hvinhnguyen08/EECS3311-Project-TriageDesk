package ca.yorku.triagedesk.ingest;

import ca.yorku.triagedesk.domain.SecurityEvent;
import ca.yorku.triagedesk.util.Json;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.List;

/** Parses a Wazuh alerts.json export: one JSON alert object per line. */
public class WazuhAlertParser implements LogParser {

    public static final String SOURCE = "wazuh";

    @Override
    public List<SecurityEvent> parse(List<String> lines, String batchId) {
        List<SecurityEvent> events = new ArrayList<>();
        for (int i = 0; i < lines.size(); i++) {
            String line = lines.get(i).strip();
            if (line.isEmpty()) {
                continue;
            }
            try {
                events.add(parseLine(line, batchId, i + 1));
            } catch (JsonProcessingException | RuntimeException e) {
                // Malformed alert: skipped, the import continues.
            }
        }
        return events;
    }

    private SecurityEvent parseLine(String line, String batchId, int lineNumber) throws JsonProcessingException {
        JsonNode alert = Json.mapper().readTree(line);
        if (alert == null || !alert.isObject()) {
            throw new IllegalArgumentException("Not a JSON object");
        }
        String timestamp = text(alert, "timestamp");
        if (timestamp == null) {
            throw new IllegalArgumentException("Alert has no timestamp");
        }
        JsonNode rule = alert.path("rule");
        JsonNode data = alert.path("data");

        List<String> mitreIds = new ArrayList<>();
        rule.path("mitre").path("id").forEach(n -> mitreIds.add(n.asText()));
        List<String> groups = new ArrayList<>();
        rule.path("groups").forEach(n -> groups.add(n.asText()));

        String user = firstNonNull(text(data, "srcuser"), text(data, "dstuser"), text(data, "user"));

        return SecurityEvent.builder(LogParser.eventId(batchId, lineNumber), batchId, parseTimestamp(timestamp))
                .source(SOURCE)
                .host(text(alert.path("agent"), "name"))
                .user(user)
                .srcIp(text(data, "srcip"))
                .message(text(rule, "description"))
                .ruleId(text(rule, "id"))
                .ruleLevel(rule.path("level").asInt(0))
                .mitreIds(mitreIds)
                .category(categoryFor(groups))
                .attribute("alertId", text(alert, "id"))
                .attribute("groups", groups.isEmpty() ? null : String.join(",", groups))
                .attribute("fullLog", text(alert, "full_log"))
                .attribute("location", text(alert, "location"))
                .attribute("file", text(alert.path("syscheck"), "path"))
                .attribute("sha256", text(alert.path("syscheck"), "sha256_after"))
                .build();
    }

    /** Wazuh writes offsets as +0000; java.time expects +00:00. */
    static Instant parseTimestamp(String value) {
        String s = value.strip();
        if (s.matches(".*[+-]\\d{4}$")) {
            s = s.substring(0, s.length() - 2) + ":" + s.substring(s.length() - 2);
        }
        return OffsetDateTime.parse(s).toInstant();
    }

    private static String categoryFor(List<String> groups) {
        if (groups.contains("authentication_failed") || groups.contains("authentication_failures")
                || groups.contains("invalid_login")) {
            return SecurityEvent.AUTH_FAILURE;
        }
        if (groups.contains("authentication_success")) {
            return SecurityEvent.AUTH_SUCCESS;
        }
        if (groups.contains("sudo")) {
            return SecurityEvent.PRIVILEGE;
        }
        return SecurityEvent.ALERT;
    }

    private static String text(JsonNode node, String field) {
        JsonNode value = node.path(field);
        if (value.isMissingNode() || value.isNull()) {
            return null;
        }
        String s = value.asText();
        return s.isBlank() ? null : s;
    }

    private static String firstNonNull(String... values) {
        for (String v : values) {
            if (v != null) {
                return v;
            }
        }
        return null;
    }
}
