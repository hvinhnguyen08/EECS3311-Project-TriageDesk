package ca.yorku.triagedesk.agent;

import java.util.List;

/**
 * The model's answer to one chat request: either final text, or one or more tool calls
 * (some models also add text next to the calls). Token counts are 0 when the service
 * does not report them.
 */
public record LlmReply(String text, List<ToolCall> toolCalls, int promptTokens, int completionTokens) {

    public LlmReply {
        text = text == null ? "" : text;
        toolCalls = toolCalls == null ? List.of() : List.copyOf(toolCalls);
    }

    public static LlmReply text(String text) {
        return new LlmReply(text, List.of(), 0, 0);
    }

    public static LlmReply withToolCalls(ToolCall... calls) {
        return new LlmReply("", List.of(calls), 0, 0);
    }

    public boolean hasToolCall() {
        return !toolCalls.isEmpty();
    }
}
