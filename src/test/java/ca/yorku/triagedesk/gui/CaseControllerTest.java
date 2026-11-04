package ca.yorku.triagedesk.gui;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ca.yorku.triagedesk.agent.LlmReply;
import ca.yorku.triagedesk.agent.MockLlmClient;
import ca.yorku.triagedesk.config.AppConfig;
import ca.yorku.triagedesk.domain.Verdict;
import ca.yorku.triagedesk.facade.SocAssistant;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class CaseControllerTest {

    @TempDir
    Path dataDir;

    private final FakeCaseView view = new FakeCaseView();
    private int changes;

    private void start(MockLlmClient llm) {
        SocAssistant assistant = SocAssistant.create(AppConfig.load(null, Map.of()), dataDir, llm);
        assistant.importFile(Path.of("samples/alerts.json"));
        assistant.importFile(Path.of("samples/auth.log"));
        assistant.runDetections();
        new CaseController(assistant, view, new DirectUiTasks(), "CASE-0001", dataDir.resolve("reports"), () -> changes++)
                .load();
    }

    @Test
    void loadRendersTheCase() {
        start(new MockLlmClient());

        assertEquals("CASE-0001", view.rendered.getId());
        assertEquals("NEW", view.rendered.getState().name());
        assertEquals(0, changes);
    }

    @Test
    void triageThenResponseThenTickingOffASteps() {
        start(new MockLlmClient(
                LlmReply.text("{\"verdict\":\"TRUE_POSITIVE\",\"confidence\":0.9,\"reasoning\":\"Brute force then login.\"}"),
                LlmReply.text("{\"steps\":[{\"action\":\"Block 203.0.113.7\"},{\"action\":\"Disable deploy\"}]}")));

        view.onTriage.run();
        assertEquals(Verdict.TRUE_POSITIVE, view.rendered.getVerdict().verdict());
        assertEquals("INVESTIGATING", view.rendered.getState().name());
        assertTrue(view.lastMessage().startsWith("AI verdict: TRUE_POSITIVE (confidence 0.90), 0 tool calls."), view.lastMessage());

        view.onRecommendResponse.run();
        assertEquals(2, view.rendered.getResponsePlan().getSteps().size());

        view.onStepDone.accept(2);
        assertTrue(view.rendered.getResponsePlan().isDone(1));
        assertEquals("Step 2 done.", view.lastMessage());
        assertEquals(3, changes);
    }

    @Test
    void statusDialogsCanBeCancelledOrConfirmed() {
        start(new MockLlmClient());

        view.escalationReason = Optional.of("too early");
        view.onChangeStatus.accept("escalate");
        assertTrue(view.errors.get(0).startsWith("Cannot escalate a case that is NEW"));

        view.onChangeStatus.accept("start");
        view.escalationReason = Optional.empty();
        view.onChangeStatus.accept("escalate");  // dialog cancelled: nothing happens
        assertEquals("INVESTIGATING", view.rendered.getState().name());

        view.escalationReason = Optional.of("deploy compromised");
        view.onChangeStatus.accept("escalate");
        assertEquals("ESCALATED", view.rendered.getState().name());

        view.closeRequest = Optional.of(new CaseView.CloseRequest("true_positive", " "));
        view.onChangeStatus.accept("close");
        assertTrue(view.errors.get(view.errors.size() - 1).contains("A comment is required"));

        view.closeRequest = Optional.of(new CaseView.CloseRequest("true_positive", "Contained"));
        view.onChangeStatus.accept("close");
        assertEquals("CLOSED", view.rendered.getState().name());
        assertEquals("CASE-0001 is now CLOSED.", view.lastMessage());
    }

    @Test
    void notesEnrichmentAndMapping() {
        start(new MockLlmClient());

        view.onAddNote.accept("Called the server owner");
        assertTrue(view.noteCleared);
        assertEquals(1, view.rendered.getNotes().size());

        view.onEnrich.run();
        assertEquals(2, view.rendered.getIocs().size());
        assertTrue(view.lastMessage().startsWith("2 indicator(s); no threat-intel provider configured"));

        view.onMapAttack.accept(false);
        assertEquals(4, view.rendered.getTechniques().size());
        assertEquals("4 technique(s): 4 from detections, 0 from the AI.", view.lastMessage());
    }

    @Test
    void failuresAreShownAndTheViewIsNotLeftBusy() {
        start(new MockLlmClient());
        view.busyChanges.clear();

        view.onTriage.run();
        view.onRecommendResponse.run();

        assertEquals("Mock LLM has no scripted reply left", view.errors.get(0));
        assertTrue(view.errors.get(1).startsWith("Run AI Triage first"));
        assertEquals(java.util.List.of(true, false, true, false), view.busyChanges);
        assertNull(view.rendered.getVerdict());
        assertEquals(0, changes);
    }

    @Test
    void reportIsWrittenEvenWithoutTheAi() throws Exception {
        start(new MockLlmClient());

        view.onGenerateReport.run();

        assertEquals(dataDir.resolve("reports").resolve("CASE-0001.md"), view.report);
        assertTrue(view.reportWarning.startsWith("AI narrative unavailable"));
        assertTrue(Files.readString(view.report).contains("[AI narrative unavailable]"));
        assertFalse(view.messages.isEmpty());
    }
}
