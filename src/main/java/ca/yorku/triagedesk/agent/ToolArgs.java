package ca.yorku.triagedesk.agent;

import ca.yorku.triagedesk.util.Json;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;

/** Parses the model's JSON arguments into plain string values, which is what the tools need. */
final class ToolArgs {

    private ToolArgs() {
    }

    /**
     * @return the arguments as strings (numbers and booleans are converted, nulls dropped)
     * @throws IllegalArgumentException if the text is not a JSON object or a value is an array/object
     */
    static Map<String, String> parse(String argsJson) {
        JsonNode root;
        try {
            root = Json.mapper().readTree(argsJson == null || argsJson.isBlank() ? "{}" : argsJson);
        } catch (JsonProcessingException e) {
            throw new IllegalArgumentException("Arguments are not valid JSON: " + argsJson);
        }
        if (root == null || !root.isObject()) {
            throw new IllegalArgumentException("Arguments must be a JSON object");
        }
        Map<String, String> args = new LinkedHashMap<>();
        Iterator<Map.Entry<String, JsonNode>> fields = root.fields();
        while (fields.hasNext()) {
            Map.Entry<String, JsonNode> f = fields.next();
            JsonNode v = f.getValue();
            if (v.isNull()) {
                continue;
            }
            if (v.isContainerNode()) {
                throw new IllegalArgumentException("Argument '" + f.getKey() + "' must be a single value");
            }
            args.put(f.getKey(), v.asText());
        }
        return args;
    }

    /** Removes and returns an integer argument, clamped to [1, max]. */
    static int takeInt(Map<String, String> args, String key, int defaultValue, int max) {
        String value = args.remove(key);
        if (value == null || value.isBlank()) {
            return defaultValue;
        }
        try {
            return Math.max(1, Math.min(max, (int) Double.parseDouble(value.strip())));
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("'" + key + "' must be a number: " + value);
        }
    }
}
