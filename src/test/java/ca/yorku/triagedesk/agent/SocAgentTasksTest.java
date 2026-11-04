package ca.yorku.triagedesk.agent;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ca.yorku.triagedesk.config.AppConfig;
import ca.yorku.triagedesk.detect.DetectionEngine;
import ca.yorku.triagedesk.domain.AgentResult;
import ca.yorku.triagedesk.domain.Case;
import ca.yorku.triagedesk.domain.TriageVerdict;
import ca.yorku.triagedesk.domain.Verdict;
import ca.yorku.triagedesk.ingest.EventStore;
import ca.yorku.triagedesk.testutil.SampleData;
import ca.yorku.triagedesk.util.Json;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class SocAgentTasksTest {

    @TempDir
    Path dataDir;

    private ToolRegistry tools;
    private Case sshCase;

    @BeforeEach
    void setUp() {
        EventStore store = new EventStore(dataDir);
        store.addEvents(SampleData.all());
        tools = new ToolRegistry().register(new SearchEventsTool(store)).register(new CountByTool(store));
        var findings = DetectionEngine.withStandardDetectors(AppConfig.load(null, Map.of())).runAll(SampleData.authLog());
        sshCase = new Case("CASE-0001", "SSH", findings, Clock.fixed(Instant.parse("2026-11-03T12:00:00Z"), ZoneOffset.UTC));
    }

    private SocAgent agent(MockLlmClient llm) {
        return new SocAgent(llm, tools, 6);
    }

    private static AgentResult result(String text) {
        return new AgentResult(text, List.of("count_by {} -> {}"), false);
    }

    @Test
    void triageSendsTheCaseFactsAndParsesTheVerdict() throws Exception {
        MockLlmClient llm = new MockLlmClient(
                LlmReply.withToolCalls(new ToolCall("c1", CountByTool.NAME,
                        "{\"field\":\"category\",\"srcIp\":\"203.0.113.7\"}")),
                LlmReply.text("```json\n{\"verdict\":\"TRUE_POSITIVE\",\"confidence\":0.9,"
                        + "\"reasoning\":\"13 failures then a successful login as deploy.\"}\n```"));

        TriageVerdict v = agent(llm).triage(sshCase);

        assertEquals(Verdict.TRUE_POSITIVE, v.verdict());
        assertEquals(0.9, v.confidence());
        assertEquals("13 failures then a successful login as deploy.", v.reasoning());
        assertEquals(1, v.toolTrace().size());

        List<ChatMessage> first = llm.getRequests().get(0);
        assertEquals(Prompts.TRIAGE, first.get(0).content());
        String prompt = first.get(1).content();
        assertTrue(prompt.contains("\"caseId\":\"CASE-0001\""));
        String json = prompt.substring(prompt.indexOf('{'), prompt.lastIndexOf('}') + 1);
        var facts = Json.mapper().readTree(json);
        assertEquals(2, facts.path("findings").size());
        assertEquals(SocAgent.EVIDENCE_SAMPLE, facts.path("evidenceSample").size());
        assertEquals(2, llm.getToolSpecs().get(0).size());
    }

    @Test
    void invalidVerdictsBecomeNeedsReview() {
        assertEquals(Verdict.NEEDS_REVIEW, SocAgent.parseVerdict(result("I think it is bad.")).verdict());
        assertTrue(SocAgent.parseVerdict(result("I think it is bad.")).reasoning().contains("did not return a JSON verdict"));
        assertEquals(Verdict.NEEDS_REVIEW, SocAgent.parseVerdict(result("{\"verdict\": \"MALICIOUS\", \"confidence\": 0.9}")).verdict());
        assertEquals(Verdict.NEEDS_REVIEW, SocAgent.parseVerdict(result("{\"verdict\": \"BENIGN\"}")).verdict());
        assertEquals(Verdict.NEEDS_REVIEW, SocAgent.parseVerdict(result("{verdict: BENIGN")).verdict());
        AgentResult stopped = new AgentResult("{\"verdict\":\"BENIGN\",\"confidence\":0.9}", List.of(), true);
        assertTrue(SocAgent.parseVerdict(stopped).reasoning().startsWith("The step limit was reached"));
    }

    @Test
    void lenientButValidVerdictFormats() {
        TriageVerdict percent = SocAgent.parseVerdict(result("{\"verdict\":\"false positive\",\"confidence\":85,\"reasoning\":\"r\"}"));
        assertEquals(Verdict.FALSE_POSITIVE, percent.verdict());
        assertEquals(0.85, percent.confidence(), 1e-9);

        TriageVerdict review = SocAgent.parseVerdict(result("{\"verdict\":\"NEEDS_REVIEW\",\"confidence\":\"0.3\",\"reasoning\":\"unclear\"}"));
        assertEquals(Verdict.NEEDS_REVIEW, review.verdict());
        assertEquals(0.3, review.confidence(), 1e-9);
        assertEquals("unclear", review.reasoning());
    }

    @Test
    void summaryToolsOnlySeeTheFile() {
        MockLlmClient llm = new MockLlmClient(
                LlmReply.withToolCalls(new ToolCall("c1", CountByTool.NAME, "{\"field\":\"source\",\"batchId\":\"alerts.json\"}")),
                LlmReply.text("auth.log has 35 events."));

        AgentResult r = agent(llm).summarize("auth.log", 35, "from a to b");

        assertEquals("auth.log has 35 events.", r.text());
        String toolResult = llm.getRequests().get(1).get(3).content();
        assertTrue(toolResult.contains("\"counts\":{\"auth\":35}"), "the model's batchId was replaced: " + toolResult);
        assertFalse(llm.getToolSpecs().get(0).get(0).contains("\"batchId\""), "batchId is hidden from the model");
        assertTrue(llm.getRequests().get(0).get(1).content().contains("'auth.log' (35 events, from a to b)"));
    }

    @Test
    void answerIncludesTheContextAndTracksTokens() {
        MockLlmClient llm = new MockLlmClient(
                new LlmReply("", List.of(new ToolCall("c1", CountByTool.NAME, "{\"field\":\"srcIp\"}")), 900, 20),
                new LlmReply("198.51.100.23 is the busiest IP.", List.of(), 1500, 15));

        SocAgent agent = agent(llm);
        AgentResult r = agent.answer("Which IP is busiest?", "98 events in 3 files");

        assertEquals("198.51.100.23 is the busiest IP.", r.text());
        assertEquals("Imported data: 98 events in 3 files\n\nQuestion: Which IP is busiest?",
                llm.getRequests().get(0).get(1).content());
        assertEquals(new TokenUsage(2400, 35, 2), agent.getLastUsage());
    }

    @Test
    void offlineResponderGathersDataButNeverClaimsAVerdict() {
        SocAgent offline = new SocAgent(new MockLlmClient(new OfflineResponder()), tools, 6);

        TriageVerdict v = offline.triage(sshCase);
        AgentResult a = offline.answer("Who is busiest?", "ctx");

        assertEquals(Verdict.NEEDS_REVIEW, v.verdict());
        assertEquals(0.0, v.confidence());
        assertTrue(v.reasoning().startsWith(OfflineResponder.NOTICE), v.reasoning());
        assertTrue(v.reasoning().contains("198.51.100.23"));
        assertEquals(1, v.toolTrace().size());
        assertTrue(a.text().startsWith(OfflineResponder.NOTICE));
    }

    @Test
    void evidenceSampleRepresentsEveryFinding() {
        var findings = new java.util.ArrayList<>(
                DetectionEngine.withStandardDetectors(AppConfig.load(null, Map.of())).runAll(SampleData.all()));
        findings.removeIf(f -> !"203.0.113.7".equals(f.srcIp()) && !"web01".equals(f.host()) || "198.51.100.23".equals(f.srcIp()));
        Case big = new Case("CASE-0009", "SSH", findings, Clock.systemUTC());

        List<String> ids = SocAgent.evidenceSample(big).stream().map(e -> e.id()).toList();

        assertEquals(SocAgent.EVIDENCE_SAMPLE, ids.size());
        assertTrue(ids.contains("alerts.json:7"), "the 09:21 authorized_keys change is shown: " + ids);
        assertTrue(ids.contains("auth.log:22"), "the successful login is shown");
        var times = SocAgent.evidenceSample(big).stream().map(e -> e.timestamp()).toList();
        assertEquals(times.stream().sorted().toList(), times, "oldest first");
    }

    @Test
    void responseStepsFromJsonOrALIst() {
        assertEquals(List.of("Block 203.0.113.7 - brute force source", "Reset the deploy password"),
                SocAgent.parseSteps("```json\n{\"steps\":[{\"action\":\"Block 203.0.113.7\",\"reason\":\"brute force source\"},"
                        + "{\"action\":\"Reset the deploy password\"},{\"action\":\" \"}]}\n```"));
        assertEquals(List.of("Block the IP", "Reset the password"),
                SocAgent.parseSteps("Here is the plan:\n1. Block the IP\n- Reset the password\nThanks"));
        assertEquals(List.of(), SocAgent.parseSteps("I cannot help with that."));
        assertEquals(SocAgent.MAX_RESPONSE_STEPS, SocAgent.parseSteps("- a\n".repeat(15)).size());

        SocAgent agent = new SocAgent(new MockLlmClient(LlmReply.text("No idea.")), tools, 6);
        assertTrue(assertThrows(IllegalStateException.class, () -> agent.recommendResponse(sshCase))
                .getMessage().startsWith("The AI did not return any usable response steps"));
    }

    @Test
    void techniqueIdsAreReadFromAnyAnswerFormat() {
        assertEquals(List.of("T1098.004", "T1548.003"),
                SocAgent.parseTechniqueIds("{\"techniques\":[{\"id\":\"t1098.004\"},{\"id\":\"T1548.003\"},{\"id\":\"T1098.004\"}]}"));
        assertEquals(List.of("T1110"), SocAgent.parseTechniqueIds("Probably T1110 (Brute Force); not XT11100."));
        assertEquals(List.of(), SocAgent.parseTechniqueIds(null));
    }

    @Test
    void scopedToolHidesAndForcesTheBatch() {
        BatchScopedTool scoped = new BatchScopedTool(tools.get(SearchEventsTool.NAME), "access.log");

        assertEquals(SearchEventsTool.NAME, scoped.name());
        assertFalse(scoped.parameters().contains("batchId"));
        assertTrue(scoped.description().endsWith("Only events from the file access.log are searched."));
        assertTrue(scoped.execute("{\"limit\":1}").contains("\"total\":51"));
        assertTrue(scoped.execute("").contains("\"total\":51"));
    }
}
