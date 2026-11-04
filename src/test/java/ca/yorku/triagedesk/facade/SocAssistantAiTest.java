package ca.yorku.triagedesk.facade;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ca.yorku.triagedesk.agent.LlmException;
import ca.yorku.triagedesk.agent.LlmReply;
import ca.yorku.triagedesk.agent.MockLlmClient;
import ca.yorku.triagedesk.config.AppConfig;
import ca.yorku.triagedesk.domain.AgentResult;
import ca.yorku.triagedesk.domain.TriageVerdict;
import ca.yorku.triagedesk.domain.Verdict;
import java.nio.file.Path;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class SocAssistantAiTest {

    private static final AppConfig CONFIG = AppConfig.load(null, Map.of());

    @TempDir
    Path dataDir;

    private SocAssistant withSamples(MockLlmClient llm) {
        SocAssistant a = SocAssistant.create(CONFIG, dataDir, llm);
        a.importFile(Path.of("samples/alerts.json"));
        a.importFile(Path.of("samples/auth.log"));
        a.importFile(Path.of("samples/access.log"));
        a.runDetections();
        return a;
    }

    @Test
    void triageStoresTheVerdictAndStartsTheInvestigation() {
        SocAssistant a = withSamples(new MockLlmClient(LlmReply.text(
                "{\"verdict\":\"TRUE_POSITIVE\",\"confidence\":0.92,\"reasoning\":\"Brute force then login.\"}")));

        TriageVerdict v = a.triageCase("CASE-0001");

        assertEquals(Verdict.TRUE_POSITIVE, v.verdict());
        SocAssistant restarted = SocAssistant.create(CONFIG, dataDir, new MockLlmClient());
        assertEquals("INVESTIGATING", restarted.getCase("CASE-0001").getState().name());
        assertEquals(v, restarted.getCase("CASE-0001").getVerdict());
    }

    @Test
    void aiFailureLeavesTheCaseUnchanged() {
        SocAssistant a = withSamples(new MockLlmClient());

        assertThrows(LlmException.class, () -> a.triageCase("CASE-0001"));

        assertEquals("NEW", a.getCase("CASE-0001").getState().name());
        assertNull(a.getCase("CASE-0001").getVerdict());
    }

    @Test
    void closedCasesAreNotTriaged() {
        SocAssistant a = withSamples(new MockLlmClient());
        a.changeStatus("CASE-0002", "close", "benign", "test");

        IllegalStateException e = assertThrows(IllegalStateException.class, () -> a.triageCase("CASE-0002"));
        assertTrue(e.getMessage().contains("reopen"));
    }

    @Test
    void summaryAndQuestionsCheckTheirInputBeforeCallingTheModel() {
        MockLlmClient llm = new MockLlmClient(LlmReply.text("summary"), LlmReply.text("answer"));
        SocAssistant empty = SocAssistant.create(CONFIG, dataDir, llm);

        assertEquals("Import a file first", assertThrows(IllegalStateException.class, () -> empty.ask("who?")).getMessage());
        assertThrows(IllegalArgumentException.class, () -> empty.ask("  "));
        IllegalArgumentException noFile = assertThrows(IllegalArgumentException.class, () -> empty.summarizeLog("auth.log"));
        assertTrue(noFile.getMessage().contains("Imported files: none"));
        assertEquals(0, llm.getRequests().size(), "no model call was made");

        empty.importFile(Path.of("samples/auth.log"));
        AgentResult summary = empty.summarizeLog("auth.log");
        AgentResult answer = empty.ask("Which IP failed most?");
        assertEquals("summary", summary.text());
        assertEquals("answer", answer.text());
        String context = llm.getRequests().get(1).get(1).content();
        assertTrue(context.startsWith("Imported data: 35 events in auth.log (35 events), from 2026-10-28T08:55:01Z to 2026-10-28T12:00:02Z"), context);
    }

    @Test
    void missingKeyOnlyAffectsTheAiFeatures() {
        AppConfig noKey = AppConfig.load(null, Map.of("LLM_PROVIDER", "openai", "LLM_BASE_URL", "https://api.openai.com/v1"));
        SocAssistant a = SocAssistant.create(noKey, dataDir);

        a.importFile(Path.of("samples/auth.log"));
        assertEquals(2, a.runDetections().findings());
        IllegalStateException e = assertThrows(IllegalStateException.class, () -> a.triageCase("CASE-0001"));
        assertTrue(e.getMessage().contains("LLM_API_KEY is not set"));
    }

    @Test
    void mockProviderRunsOffline() {
        SocAssistant a = SocAssistant.create(CONFIG, dataDir);
        a.importFile(Path.of("samples/auth.log"));
        a.runDetections();

        TriageVerdict v = a.triageCase("CASE-0001");

        assertEquals(Verdict.NEEDS_REVIEW, v.verdict());
        assertTrue(v.reasoning().startsWith("Offline mode"));
        assertEquals("mock (offline, scripted replies)", a.describeModel());
        assertEquals(2, a.getLastUsage().modelCalls());
    }
}
