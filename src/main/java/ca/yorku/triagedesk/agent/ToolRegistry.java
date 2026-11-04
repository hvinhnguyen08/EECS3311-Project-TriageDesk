package ca.yorku.triagedesk.agent;

import ca.yorku.triagedesk.util.Json;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** The tools available to the agent, looked up by the name the model uses. */
public class ToolRegistry {

    private final Map<String, Tool> tools = new LinkedHashMap<>();

    public ToolRegistry register(Tool t) {
        if (tools.containsKey(t.name())) {
            throw new IllegalArgumentException("A tool named " + t.name() + " is already registered");
        }
        tools.put(t.name(), t);
        return this;
    }

    /** @throws IllegalArgumentException if no tool has that name */
    public Tool get(String name) {
        Tool t = tools.get(name);
        if (t == null) {
            throw new IllegalArgumentException("Unknown tool '" + name + "'. Available: " + String.join(", ", tools.keySet()));
        }
        return t;
    }

    public boolean has(String name) {
        return tools.containsKey(name);
    }

    public List<String> names() {
        return List.copyOf(tools.keySet());
    }

    /** One {"name", "description", "parameters"} JSON object per requested tool, for LlmClient.chat. */
    public List<String> specs(List<String> names) {
        List<String> specs = new ArrayList<>();
        for (String name : names) {
            Tool t = get(name);
            ObjectNode spec = Json.mapper().createObjectNode();
            spec.put("name", t.name());
            spec.put("description", t.description());
            try {
                spec.set("parameters", Json.mapper().readTree(t.parameters()));
            } catch (JsonProcessingException e) {
                throw new IllegalStateException("Tool " + t.name() + " has an invalid parameter schema", e);
            }
            specs.add(spec.toString());
        }
        return specs;
    }
}
