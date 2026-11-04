package ca.yorku.triagedesk.agent;

import ca.yorku.triagedesk.domain.SecurityEvent;
import ca.yorku.triagedesk.util.Json;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Argument schema and event formatting shared by search_events and count_by. */
final class EventToolSupport {

    private static final int MESSAGE_CHARS = 200;
    private static final List<String> SHOWN_ATTRIBUTES =
            List.of("status", "method", "path", "userAgent", "command", "denied", "groups", "file", "sha256");

    private EventToolSupport() {
    }

    /** The filter properties both tools accept; they map onto EventStore.search criteria. */
    static ObjectNode filterSchema() {
        ObjectNode schema = Json.mapper().createObjectNode();
        schema.put("type", "object");
        ObjectNode p = schema.putObject("properties");
        string(p, "batchId", "Imported file name, for example auth.log");
        ArrayNode sources = string(p, "source", "Log format").putArray("enum");
        sources.add("wazuh").add("auth").add("apache");
        string(p, "host", "Host name, for example web01");
        string(p, "user", "User account name");
        string(p, "srcIp", "Source IP address");
        ArrayNode categories = string(p, "category", "Normalised event type").putArray("enum");
        for (String c : List.of(SecurityEvent.AUTH_FAILURE, SecurityEvent.AUTH_SUCCESS, SecurityEvent.PRIVILEGE,
                SecurityEvent.WEB_REQUEST, SecurityEvent.ALERT, SecurityEvent.OTHER)) {
            categories.add(c);
        }
        string(p, "ruleId", "Wazuh rule ID");
        string(p, "text", "Case-insensitive text that must appear in the event message");
        string(p, "since", "Only events at or after this ISO-8601 time, for example 2026-10-28T09:00:00Z");
        string(p, "until", "Only events at or before this ISO-8601 time");
        integer(p, "minLevel", "Minimum Wazuh rule level");
        return schema;
    }

    static ObjectNode string(ObjectNode properties, String name, String description) {
        ObjectNode node = properties.putObject(name);
        node.put("type", "string");
        node.put("description", description);
        return node;
    }

    static ObjectNode integer(ObjectNode properties, String name, String description) {
        ObjectNode node = properties.putObject(name);
        node.put("type", "integer");
        node.put("description", description);
        return node;
    }

    /** A compact view of one event for the model: core fields, a shortened message and useful attributes. */
    static Map<String, Object> summarise(SecurityEvent e) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", e.id());
        m.put("time", e.timestamp().toString());
        m.put("source", e.source());
        putIfPresent(m, "host", e.host());
        putIfPresent(m, "user", e.user());
        putIfPresent(m, "srcIp", e.srcIp());
        m.put("category", e.category());
        putIfPresent(m, "ruleId", e.ruleId());
        if (e.ruleLevel() > 0) {
            m.put("level", e.ruleLevel());
        }
        if (!e.mitreIds().isEmpty()) {
            m.put("mitre", e.mitreIds());
        }
        String msg = e.message();
        m.put("message", msg.length() > MESSAGE_CHARS ? msg.substring(0, MESSAGE_CHARS) + "..." : msg);
        for (String a : SHOWN_ATTRIBUTES) {
            putIfPresent(m, a, e.attribute(a));
        }
        return m;
    }

    static String toJson(Object value) {
        try {
            return Json.mapper().writeValueAsString(value);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Could not format tool result", e);
        }
    }

    private static void putIfPresent(Map<String, Object> m, String key, String value) {
        if (value != null) {
            m.put(key, value);
        }
    }
}
