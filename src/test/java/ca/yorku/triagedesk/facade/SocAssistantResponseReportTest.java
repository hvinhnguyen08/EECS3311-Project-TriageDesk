package ca.yorku.triagedesk.facade;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ca.yorku.triagedesk.agent.LlmReply;
import ca.yorku.triagedesk.agent.MockLlmClient;
import ca.yorku.triagedesk.config.AppConfig;
import ca.yorku.triagedesk.domain.ResponsePlan;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class SocAssistantResponseReportTest {

    private static final AppConfig CONFIG = AppConfig.load(null, Map.of());
    private static final String TP = "{\"verdict\":\"TRUE_POSITIVE\",\"confidence\":0.9,\"reasoning\":\"Brute force then login.\"}";
    private static final String FP = "{\"verdict\":\"FALSE_POSITIVE\",\"confidence\":0.8,\"reasoning\":\"Scheduled scan.\"}";

    @TempDir
    Path dataDir;

    private SocAssistant assistant(MockLlmClient llm) {
        SocAssistant a = SocAssistant.create(CONFIG, dataDir, llm);
        a.importFile(Path.of("samples/auth.log"));
        a.runDetections();
        return a;
    }

    @Test
    void responseNeedsATriageVerdict() {
        MockLlmClient llm = new MockLlmClient();
        SocAssistant a = assistant(llm);

        IllegalStateException e = assertThrows(IllegalStateException.class, () -> a.recommendResponse("CASE-0001"));
        assertTrue(e.getMessage().startsWith("Run AI Triage first"));
        assertEquals(0, llm.getRequests().size());
    }

    @Test
    void falsePositiveGetsOneStepWithoutCallingTheAi() {
        MockLlmClient llm = new MockLlmClient(LlmReply.text(FP));
        SocAssistant a = assistant(llm);
        a.triageCase("CASE-0001");

        ResponsePlan plan = a.recommendResponse("CASE-0001");

        assertEquals(List.of("Document why the activity is a false positive in a note, then close the case as false_positive"),
                plan.getSteps());
        assertEquals(1, llm.getRequests().size(), "only the triage call");
    }

    @Test
    void truePositiveStepsComeFromTheAgentAndAreTickedOff() {
        MockLlmClient llm = new MockLlmClient(LlmReply.text(TP), LlmReply.text("{\"steps\":["
                + "{\"action\":\"Block 203.0.113.7 at the firewall\",\"reason\":\"source of the brute force\"},"
                + "{\"action\":\"Disable the deploy account\",\"reason\":\"logged in after 13 failures\"}]}"));
        SocAssistant a = assistant(llm);
        a.triageCase("CASE-0001");

        ResponsePlan plan = a.recommendResponse("CASE-0001");
        a.markStepDone("CASE-0001", 2);

        assertEquals("Block 203.0.113.7 at the firewall - source of the brute force", plan.getSteps().get(0));
        String prompt = llm.getRequests().get(1).get(1).content();
        assertTrue(prompt.contains("\"triageVerdict\":{\"verdict\":\"TRUE_POSITIVE\""), prompt);
        ResponsePlan saved = SocAssistant.create(CONFIG, dataDir, new MockLlmClient()).getCase("CASE-0001").getResponsePlan();
        assertFalse(saved.isDone(0));
        assertTrue(saved.isDone(1));
        assertThrows(IndexOutOfBoundsException.class, () -> a.markStepDone("CASE-0001", 3));
    }

    @Test
    void reportIncludesTheNarrativeOrAPlaceholder() throws Exception {
        MockLlmClient llm = new MockLlmClient(LlmReply.text("### Executive summary\nThe deploy account was compromised."));
        SocAssistant a = assistant(llm);

        ReportResult ok = a.generateReport("CASE-0001", dataDir.resolve("reports/r1.md"));
        ReportResult failed = a.generateReport("CASE-0001", dataDir.resolve("reports/r2.md"));

        assertTrue(ok.aiNarrative());
        assertNull(ok.warning());
        assertTrue(Files.readString(ok.path()).contains("The deploy account was compromised."));
        assertFalse(failed.aiNarrative());
        assertTrue(failed.warning().startsWith("AI narrative unavailable"));
        assertTrue(Files.readString(failed.path()).contains("[AI narrative unavailable]"));
    }
}
