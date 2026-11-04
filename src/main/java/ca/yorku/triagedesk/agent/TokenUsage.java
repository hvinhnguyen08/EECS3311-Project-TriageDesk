package ca.yorku.triagedesk.agent;

/** Tokens used by one agent task, summed over all its model calls (0 if the service does not report them). */
public record TokenUsage(int promptTokens, int completionTokens, int modelCalls) {

    public static final TokenUsage NONE = new TokenUsage(0, 0, 0);

    TokenUsage plus(LlmReply reply) {
        return new TokenUsage(promptTokens + reply.promptTokens(), completionTokens + reply.completionTokens(), modelCalls + 1);
    }
}
