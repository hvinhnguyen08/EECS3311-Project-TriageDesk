package ca.yorku.triagedesk.domain;

import java.util.List;

/**
 * Final text produced by the agent, the tool calls it made to get there, and whether
 * it stopped at the step limit before finishing (the answer is then incomplete).
 */
public record AgentResult(String text, List<String> toolTrace, boolean stoppedEarly) {

    public AgentResult {
        text = text == null ? "" : text;
        toolTrace = toolTrace == null ? List.of() : List.copyOf(toolTrace);
    }
}
