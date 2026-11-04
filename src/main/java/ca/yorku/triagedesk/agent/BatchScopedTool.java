package ca.yorku.triagedesk.agent;

import ca.yorku.triagedesk.util.Json;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.util.Objects;

/**
 * Decorator for an event tool: same name and behaviour, but every call is limited to one
 * imported file. Whatever batchId the model sends is replaced, so a log summary (F04)
 * cannot drift into other files' events, and the batchId argument is hidden from the model.
 */
public class BatchScopedTool implements Tool {

    private final Tool inner;
    private final String batchId;

    public BatchScopedTool(Tool inner, String batchId) {
        this.inner = Objects.requireNonNull(inner, "inner");
        this.batchId = Objects.requireNonNull(batchId, "batchId");
    }

    @Override
    public String name() {
        return inner.name();
    }

    @Override
    public String description() {
        return inner.description() + " Only events from the file " + batchId + " are searched.";
    }

    @Override
    public String parameters() {
        try {
            ObjectNode schema = (ObjectNode) Json.mapper().readTree(inner.parameters());
            JsonNode props = schema.get("properties");
            if (props instanceof ObjectNode p) {
                p.remove("batchId");
            }
            return schema.toString();
        } catch (JsonProcessingException | ClassCastException e) {
            return inner.parameters();
        }
    }

    @Override
    public String execute(String argsJson) {
        ObjectNode args;
        try {
            JsonNode parsed = Json.mapper().readTree(argsJson == null || argsJson.isBlank() ? "{}" : argsJson);
            if (!(parsed instanceof ObjectNode o)) {
                throw new IllegalArgumentException("Arguments must be a JSON object");
            }
            args = o;
        } catch (JsonProcessingException e) {
            throw new IllegalArgumentException("Arguments are not valid JSON: " + argsJson);
        }
        args.put("batchId", batchId);
        return inner.execute(args.toString());
    }
}
