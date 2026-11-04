package ca.yorku.triagedesk.agent;

import ca.yorku.triagedesk.domain.AgentResult;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * The AI agent. Its loop sends a task and the tools allowed for it to the model; when the
 * model asks for a tool, the agent executes it (Invoker of the Command pattern) and sends
 * the result back, until the model gives a final answer or the step limit is reached.
 * The model's choice of tools is real decision making: which data to look at next depends
 * on what earlier tool calls returned.
 */
public class SocAgent {

    /** Tool results longer than this are cut, to keep requests within free-tier token limits. */
    static final int MAX_TOOL_RESULT_CHARS = 6000;
    private static final int TRACE_RESULT_CHARS = 120;

    static final String STEP_LIMIT_PROMPT = "You have reached the limit of tool calls for this task."
            + " Answer now using only the information you already have, and say what you could not check.";

    private final LlmClient llm;
    private final ToolRegistry tools;
    private final int maxSteps;

    public SocAgent(LlmClient llm, ToolRegistry tools, int maxSteps) {
        if (maxSteps < 1) {
            throw new IllegalArgumentException("maxSteps must be at least 1");
        }
        this.llm = Objects.requireNonNull(llm, "llm");
        this.tools = Objects.requireNonNull(tools, "tools");
        this.maxSteps = maxSteps;
    }

    /**
     * Runs the tool-use loop. Each step is one model call; every tool the model requests in
     * that step is executed. A failing or unavailable tool does not stop the loop: its error
     * is returned to the model as the tool result. When the step limit is reached the model
     * is asked once more, without tools, for its best answer, and the result is marked as
     * stopped early.
     *
     * @throws LlmException if the model cannot be reached
     */
    AgentResult runLoop(String system, String prompt, List<String> toolNames) {
        List<ChatMessage> messages = new ArrayList<>();
        messages.add(ChatMessage.system(system));
        messages.add(ChatMessage.user(prompt));
        List<String> specs = tools.specs(toolNames);
        List<String> trace = new ArrayList<>();

        for (int step = 0; step < maxSteps; step++) {
            LlmReply reply = llm.chat(messages, specs);
            if (!reply.hasToolCall()) {
                return new AgentResult(reply.text(), trace, false);
            }
            messages.add(ChatMessage.assistantToolCalls(reply.text().isEmpty() ? null : reply.text(), reply.toolCalls()));
            for (ToolCall call : reply.toolCalls()) {
                String result = execute(call, toolNames);
                trace.add(traceEntry(call, result));
                messages.add(ChatMessage.toolResult(call, result));
            }
        }

        messages.add(ChatMessage.user(STEP_LIMIT_PROMPT));
        LlmReply last = llm.chat(messages, List.of());
        return new AgentResult(last.text(), trace, true);
    }

    private String execute(ToolCall call, List<String> allowed) {
        if (!allowed.contains(call.name()) || !tools.has(call.name())) {
            return "ERROR: tool '" + call.name() + "' is not available for this task. Available tools: "
                    + String.join(", ", allowed);
        }
        String result;
        try {
            result = tools.get(call.name()).execute(call.argumentsJson());
        } catch (RuntimeException e) {
            result = "ERROR: " + (e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName());
        }
        if (result == null) {
            result = "";
        }
        if (result.length() > MAX_TOOL_RESULT_CHARS) {
            result = result.substring(0, MAX_TOOL_RESULT_CHARS) + "... [truncated: use filters or a smaller limit]";
        }
        return result;
    }

    /** One line per tool call for the analyst: what was called with which arguments, and what came back. */
    static String traceEntry(ToolCall call, String result) {
        String oneLine = result.replaceAll("\\s+", " ");
        String shown = oneLine.length() > TRACE_RESULT_CHARS ? oneLine.substring(0, TRACE_RESULT_CHARS) + "..." : oneLine;
        return call.name() + " " + call.argumentsJson().replaceAll("\\s+", " ") + " -> " + shown;
    }

    public String describeModel() {
        return llm.describe();
    }

    public int getMaxSteps() {
        return maxSteps;
    }
}
