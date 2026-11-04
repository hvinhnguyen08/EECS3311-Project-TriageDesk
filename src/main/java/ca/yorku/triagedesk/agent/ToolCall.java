package ca.yorku.triagedesk.agent;

import java.util.Objects;

/**
 * A request from the model to run one tool. {@code id} links the tool's result message
 * back to this request; {@code argumentsJson} is the JSON object the model produced.
 */
public record ToolCall(String id, String name, String argumentsJson) {

    public ToolCall {
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(name, "name");
        argumentsJson = argumentsJson == null || argumentsJson.isBlank() ? "{}" : argumentsJson;
    }
}
