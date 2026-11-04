package ca.yorku.triagedesk.agent;

import java.util.List;
import java.util.Objects;

/**
 * One message of a conversation with the model. Besides plain system/user/assistant text,
 * the tool protocol needs assistant messages that carry tool calls and "tool" messages that
 * carry a tool's result, linked by the tool call ID.
 */
public record ChatMessage(String role, String content, List<ToolCall> toolCalls, String toolCallId, String toolName) {

    public static final String SYSTEM = "system";
    public static final String USER = "user";
    public static final String ASSISTANT = "assistant";
    public static final String TOOL = "tool";

    public ChatMessage {
        Objects.requireNonNull(role, "role");
        toolCalls = toolCalls == null ? List.of() : List.copyOf(toolCalls);
        if (role.equals(TOOL) && toolCallId == null) {
            throw new IllegalArgumentException("A tool result needs the ID of the tool call it answers");
        }
    }

    public static ChatMessage system(String content) {
        return new ChatMessage(SYSTEM, content, null, null, null);
    }

    public static ChatMessage user(String content) {
        return new ChatMessage(USER, content, null, null, null);
    }

    public static ChatMessage assistant(String content) {
        return new ChatMessage(ASSISTANT, content, null, null, null);
    }

    /** The assistant turn in which the model asked for tools; it must be sent back with the results. */
    public static ChatMessage assistantToolCalls(String content, List<ToolCall> calls) {
        return new ChatMessage(ASSISTANT, content, calls, null, null);
    }

    public static ChatMessage toolResult(ToolCall call, String result) {
        return new ChatMessage(TOOL, result, null, call.id(), call.name());
    }

    public boolean hasToolCalls() {
        return !toolCalls.isEmpty();
    }
}
