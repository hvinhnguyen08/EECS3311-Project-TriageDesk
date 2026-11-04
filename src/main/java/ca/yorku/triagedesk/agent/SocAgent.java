package ca.yorku.triagedesk.agent;

import ca.yorku.triagedesk.domain.AgentResult;
import ca.yorku.triagedesk.domain.Case;
import ca.yorku.triagedesk.domain.Finding;
import ca.yorku.triagedesk.domain.SecurityEvent;
import ca.yorku.triagedesk.domain.TriageVerdict;
import ca.yorku.triagedesk.domain.Verdict;
import ca.yorku.triagedesk.util.Json;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

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
    /** How many evidence events are put in the triage prompt; the model can fetch more with tools. */
    static final int EVIDENCE_SAMPLE = 12;

    static final int MAX_SUGGESTED_TECHNIQUES = 8;
    private static final Pattern TECHNIQUE_ID =
            Pattern.compile("(?i)\\bT\\d{4}(?:\\.\\d{3})?\\b");

    static final String STEP_LIMIT_PROMPT = "You have reached the limit of tool calls for this task."
            + " Answer now using only the information you already have, and say what you could not check.";

    private static final List<String> EVENT_TOOLS = List.of(SearchEventsTool.NAME, CountByTool.NAME);
    /** Triage and questions may also check indicator reputations; the summary only reads the file. */
    private static final List<String> INVESTIGATION_TOOLS = List.of(SearchEventsTool.NAME, CountByTool.NAME, LookupIocTool.NAME);

    private final LlmClient llm;
    private final ToolRegistry tools;
    private final int maxSteps;
    private volatile TokenUsage lastUsage = TokenUsage.NONE;

    public SocAgent(LlmClient llm, ToolRegistry tools, int maxSteps) {
        if (maxSteps < 1) {
            throw new IllegalArgumentException("maxSteps must be at least 1");
        }
        this.llm = Objects.requireNonNull(llm, "llm");
        this.tools = Objects.requireNonNull(tools, "tools");
        this.maxSteps = maxSteps;
    }

    // F06

    /**
     * Investigates a case with the event tools and returns the model's verdict. Output that is
     * not a valid JSON verdict, or a run that hit the step limit, gives NEEDS_REVIEW with the raw text.
     *
     * @throws LlmException if the model cannot be reached
     */
    public TriageVerdict triage(Case c) {
        String prompt = "Investigate this case and give your verdict.\n\nCase facts (JSON):\n" + caseFacts(c)
                + "\n\nThe evidence sample shows at most " + EVIDENCE_SAMPLE + " events; use the tools to look further.";
        AgentResult r = runLoop(Prompts.TRIAGE, prompt, tools, available(INVESTIGATION_TOOLS));
        return parseVerdict(r);
    }

    // F08

    /**
     * Suggests ATT&CK technique IDs for a case. The model gets the case facts and the event
     * tools, so it can check what happened after the detected activity. The IDs are not
     * trusted here; AttackMapper keeps only the ones in its catalogue.
     *
     * @throws LlmException if the model cannot be reached
     */
    public List<String> suggestTechniques(Case c) {
        LinkedHashSet<String> known = new LinkedHashSet<>();
        c.getFindings().forEach(f -> known.addAll(f.techniqueIds()));
        String prompt = "Map this case to ATT&CK techniques.\n\nCase facts (JSON):\n" + caseFacts(c)
                + "\n\nTechniques already mapped from the detections: " + (known.isEmpty() ? "none" : String.join(", ", known))
                + ".\nSuggest only ADDITIONAL techniques that the evidence shows and these miss (check the events with the"
                + " tools first); return an empty list if there are none.";
        AgentResult r = runLoop(Prompts.ATTACK, prompt, tools, available(EVENT_TOOLS));
        return parseTechniqueIds(r.text());
    }

    /** Every distinct technique ID in the text, in order, at most {@value #MAX_SUGGESTED_TECHNIQUES}. */
    static List<String> parseTechniqueIds(String text) {
        LinkedHashSet<String> ids = new LinkedHashSet<>();
        Matcher m = TECHNIQUE_ID.matcher(text == null ? "" : text);
        while (m.find() && ids.size() < MAX_SUGGESTED_TECHNIQUES) {
            ids.add(m.group().toUpperCase(Locale.ROOT));
        }
        return List.copyOf(ids);
    }

    // F04

    /**
     * Summarises one imported file. The event tools are wrapped so they only see that file.
     *
     * @throws LlmException if the model cannot be reached
     */
    public AgentResult summarize(String batchId, int eventCount, String timeRange) {
        ToolRegistry scoped = new ToolRegistry();
        for (String name : available(EVENT_TOOLS)) {
            scoped.register(new BatchScopedTool(tools.get(name), batchId));
        }
        String prompt = "Summarise the imported file '" + batchId + "' (" + eventCount + " events, " + timeRange
                + "). The tools only see this file.";
        return runLoop(Prompts.SUMMARY, prompt, scoped, scoped.names());
    }

    // F12

    /**
     * Answers a free-form question about the imported data.
     *
     * @param context a short description of what is loaded (files, event counts, time range)
     * @throws LlmException if the model cannot be reached
     */
    public AgentResult answer(String question, String context) {
        String prompt = "Imported data: " + context + "\n\nQuestion: " + question;
        return runLoop(Prompts.ANSWER, prompt, tools, available(INVESTIGATION_TOOLS));
    }

    /** Tokens used by the most recent task (for the GUI/CLI and the AI cost record). */
    public TokenUsage getLastUsage() {
        return lastUsage;
    }

    public String describeModel() {
        return llm.describe();
    }

    public int getMaxSteps() {
        return maxSteps;
    }

    AgentResult runLoop(String system, String prompt, List<String> toolNames) {
        return runLoop(system, prompt, tools, toolNames);
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
    AgentResult runLoop(String system, String prompt, ToolRegistry registry, List<String> toolNames) {
        List<ChatMessage> messages = new ArrayList<>();
        messages.add(ChatMessage.system(system));
        messages.add(ChatMessage.user(prompt));
        List<String> specs = registry.specs(toolNames);
        List<String> trace = new ArrayList<>();
        TokenUsage usage = TokenUsage.NONE;

        try {
            for (int step = 0; step < maxSteps; step++) {
                LlmReply reply = llm.chat(messages, specs);
                usage = usage.plus(reply);
                if (!reply.hasToolCall()) {
                    return new AgentResult(reply.text(), trace, false);
                }
                messages.add(ChatMessage.assistantToolCalls(reply.text().isEmpty() ? null : reply.text(), reply.toolCalls()));
                for (ToolCall call : reply.toolCalls()) {
                    String result = execute(registry, call, toolNames);
                    trace.add(traceEntry(call, result));
                    messages.add(ChatMessage.toolResult(call, result));
                }
            }

            messages.add(ChatMessage.user(STEP_LIMIT_PROMPT));
            LlmReply last = llm.chat(messages, List.of());
            usage = usage.plus(last);
            return new AgentResult(last.text(), trace, true);
        } finally {
            lastUsage = usage;
        }
    }

    private String execute(ToolRegistry registry, ToolCall call, List<String> allowed) {
        if (!allowed.contains(call.name()) || !registry.has(call.name())) {
            return "ERROR: tool '" + call.name() + "' is not available for this task. Available tools: "
                    + String.join(", ", allowed);
        }
        String result;
        try {
            result = registry.get(call.name()).execute(call.argumentsJson());
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

    /** The case as compact JSON for the triage prompt: findings, a sample of evidence, IOCs and notes. */
    static String caseFacts(Case c) {
        Map<String, Object> facts = new LinkedHashMap<>();
        facts.put("caseId", c.getId());
        facts.put("title", c.getTitle());
        facts.put("severity", c.getSeverity().name());
        facts.put("state", c.getState().name());
        List<Map<String, Object>> findings = new ArrayList<>();
        for (Finding f : c.getFindings()) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("detector", f.detector());
            m.put("title", f.title());
            m.put("severity", f.severity().name());
            if (f.srcIp() != null) m.put("srcIp", f.srcIp());
            if (f.host() != null) m.put("host", f.host());
            if (f.user() != null) m.put("user", f.user());
            m.put("attackTechniqueIds", f.techniqueIds());
            m.put("firstSeen", f.firstSeen().toString());
            m.put("lastSeen", f.lastSeen().toString());
            m.put("eventCount", f.events().size());
            findings.add(m);
        }
        facts.put("findings", findings);
        List<SecurityEvent> events = c.getEvents();
        facts.put("evidenceEventCount", events.size());
        facts.put("evidenceSample", evidenceSample(c).stream().map(EventToolSupport::summarise).toList());
        if (!c.getIocs().isEmpty()) {
            facts.put("iocs", c.getIocs());
        }
        if (!c.getNotes().isEmpty()) {
            facts.put("analystNotes", c.getNotes());
        }
        return EventToolSupport.toJson(facts);
    }

    /**
     * Up to {@value #EVIDENCE_SAMPLE} events, oldest first, that represent every finding: the
     * first and last event of each finding are always included, then the gaps are filled with
     * the earliest remaining events. (Taking only the earliest events would show one brute-force
     * burst and hide a later finding such as a file change.)
     */
    static List<SecurityEvent> evidenceSample(Case c) {
        LinkedHashMap<String, SecurityEvent> chosen = new LinkedHashMap<>();
        for (Finding f : c.getFindings()) {
            List<SecurityEvent> ev = f.events();
            for (SecurityEvent e : List.of(ev.get(0), ev.get(ev.size() - 1))) {
                if (chosen.size() < EVIDENCE_SAMPLE) {
                    chosen.putIfAbsent(e.id(), e);
                }
            }
        }
        for (SecurityEvent e : c.getEvents()) {
            if (chosen.size() >= EVIDENCE_SAMPLE) {
                break;
            }
            chosen.putIfAbsent(e.id(), e);
        }
        List<SecurityEvent> sample = new ArrayList<>(chosen.values());
        sample.sort(Comparator.comparing(SecurityEvent::timestamp));
        return sample;
    }

    /** Validates the model's final answer; anything that is not a usable verdict becomes NEEDS_REVIEW. */
    static TriageVerdict parseVerdict(AgentResult r) {
        if (r.stoppedEarly()) {
            return TriageVerdict.needsReview("The step limit was reached before a verdict. " + r.text(), r.toolTrace());
        }
        String text = r.text().strip();
        int start = text.indexOf('{');
        int end = text.lastIndexOf('}');
        if (start < 0 || end < start) {
            return TriageVerdict.needsReview("The model did not return a JSON verdict: " + text, r.toolTrace());
        }
        JsonNode json;
        try {
            json = Json.mapper().readTree(text.substring(start, end + 1));
        } catch (JsonProcessingException e) {
            return TriageVerdict.needsReview("The model's verdict is not valid JSON: " + text, r.toolTrace());
        }
        String verdictText = json.path("verdict").asText("");
        Verdict verdict = Verdict.parse(verdictText);
        String reasoning = json.path("reasoning").asText("");
        if (verdict == Verdict.NEEDS_REVIEW && !verdictText.strip().toUpperCase(Locale.ROOT).replace(' ', '_').equals("NEEDS_REVIEW")) {
            return TriageVerdict.needsReview("Unknown verdict '" + verdictText + "'. " + reasoning, r.toolTrace());
        }
        double confidence = json.path("confidence").asDouble(Double.NaN);
        if (confidence > 1 && confidence <= 100) {
            confidence /= 100;  // some models answer 85 instead of 0.85
        }
        if (Double.isNaN(confidence) || confidence < 0 || confidence > 1) {
            return TriageVerdict.needsReview("Missing or invalid confidence. " + reasoning, r.toolTrace());
        }
        return new TriageVerdict(verdict, confidence, reasoning, r.toolTrace());
    }

    private List<String> available(List<String> names) {
        return names.stream().filter(tools::has).toList();
    }
}
