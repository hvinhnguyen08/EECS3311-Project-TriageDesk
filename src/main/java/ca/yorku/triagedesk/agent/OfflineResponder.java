package ca.yorku.triagedesk.agent;

import ca.yorku.triagedesk.util.Json;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.util.List;
import java.util.function.Function;

/**
 * Responder for MockLlmClient when LLM_PROVIDER=mock: lets the GUI and CLI run without an
 * AI service. It makes one real tool call (count_by srcIp) and then reports the tool result,
 * clearly labelled as offline. It does not pretend to assess anything: a triage always comes
 * back as NEEDS_REVIEW.
 */
public class OfflineResponder implements Function<List<ChatMessage>, LlmReply> {

    static final String NOTICE = "Offline mode: no AI model is configured (LLM_PROVIDER=mock), so the data below was"
            + " gathered with the tools but not assessed.";
    private static final int SHOWN_CHARS = 600;

    @Override
    public LlmReply apply(List<ChatMessage> messages) {
        List<ChatMessage> toolResults = messages.stream().filter(m -> m.role().equals(ChatMessage.TOOL)).toList();
        boolean toolsOffered = messages.stream().noneMatch(m -> m.content() != null
                && m.content().equals(SocAgent.STEP_LIMIT_PROMPT));
        if (toolResults.isEmpty() && toolsOffered) {
            return LlmReply.withToolCalls(new ToolCall("offline_1", CountByTool.NAME, "{\"field\":\"srcIp\",\"top\":5}"));
        }
        String data = toolResults.isEmpty() ? "(no tool results)" : toolResults.get(toolResults.size() - 1).content();
        if (data.length() > SHOWN_CHARS) {
            data = data.substring(0, SHOWN_CHARS) + "...";
        }
        String report = NOTICE + " Events by source IP: " + data;

        boolean triage = !messages.isEmpty() && Prompts.TRIAGE.equals(messages.get(0).content());
        if (triage) {
            ObjectNode verdict = Json.mapper().createObjectNode();
            verdict.put("verdict", "NEEDS_REVIEW");
            verdict.put("confidence", 0.0);
            verdict.put("reasoning", report);
            return LlmReply.text(verdict.toString());
        }
        return LlmReply.text(report);
    }
}
