package ca.yorku.triagedesk.gui;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ca.yorku.triagedesk.agent.LlmReply;
import ca.yorku.triagedesk.agent.MockLlmClient;
import ca.yorku.triagedesk.agent.ToolCall;
import ca.yorku.triagedesk.config.AppConfig;
import ca.yorku.triagedesk.domain.AgentResult;
import ca.yorku.triagedesk.domain.DashboardStats;
import ca.yorku.triagedesk.facade.SocAssistant;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class DashboardAndChatControllerTest {

    @TempDir
    Path dataDir;

    private static final class FakeDashboard implements DashboardView {
        DashboardStats stats;
        List<String> files;
        Runnable onRefresh;
        public void render(DashboardStats s, List<String> f) { stats = s; files = f; }
        public void showError(String message) { throw new AssertionError(message); }
        public void setOnRefresh(Runnable handler) { onRefresh = handler; }
    }

    private static final class FakeChat implements ChatView {
        String question;
        AgentResult answer;
        String usage;
        boolean cleared;
        final List<String> errors = new ArrayList<>();
        final List<Boolean> busy = new ArrayList<>();
        Consumer<String> onAsk;
        public void showAnswer(String q, AgentResult a, String u) { question = q; answer = a; usage = u; }
        public void showError(String message) { errors.add(message); }
        public void setBusy(boolean b, String what) { busy.add(b); }
        public void clearQuestion() { cleared = true; }
        public void setOnAsk(Consumer<String> handler) { onAsk = handler; }
    }

    @Test
    void dashboardShowsTheCurrentTotals() {
        SocAssistant assistant = SocAssistant.create(AppConfig.load(null, Map.of()), dataDir, new MockLlmClient());
        FakeDashboard view = new FakeDashboard();
        DashboardController controller = new DashboardController(assistant, view, new DirectUiTasks());

        controller.refresh();
        assertTrue(view.stats.isEmpty());

        assistant.importFile(Path.of("samples/auth.log"));
        assistant.runDetections();
        view.onRefresh.run();

        assertEquals(35, view.stats.totalEvents());
        assertEquals(List.of("auth.log"), view.files);
        assertEquals("203.0.113.7", view.stats.topSourceIps().keySet().iterator().next());
        assertEquals(1, view.stats.casesByState().get("NEW"));
    }

    @Test
    void chatAnswersWithToolCallsAndUsage() {
        MockLlmClient llm = new MockLlmClient(
                new LlmReply("", List.of(new ToolCall("c1", "count_by", "{\"field\":\"srcIp\",\"category\":\"auth_failure\"}")), 800, 20),
                new LlmReply("203.0.113.7 failed 13 times and then logged in as deploy.", List.of(), 1200, 25));
        SocAssistant assistant = SocAssistant.create(AppConfig.load(null, Map.of()), dataDir, llm);
        assistant.importFile(Path.of("samples/auth.log"));
        FakeChat view = new FakeChat();
        new ChatController(assistant, view, new DirectUiTasks());

        view.onAsk.accept("  Which IP failed most?  ");

        assertEquals("Which IP failed most?", view.question);
        assertEquals("203.0.113.7 failed 13 times and then logged in as deploy.", view.answer.text());
        assertEquals(1, view.answer.toolTrace().size());
        assertEquals("2 model call(s), 2000 + 45 tokens", view.usage);
        assertTrue(view.cleared);
        assertEquals(List.of(true, false), view.busy);
    }

    @Test
    void chatRefusesEmptyQuestionsAndReportsFailures() {
        SocAssistant assistant = SocAssistant.create(AppConfig.load(null, Map.of()), dataDir, new MockLlmClient());
        FakeChat view = new FakeChat();
        new ChatController(assistant, view, new DirectUiTasks());

        view.onAsk.accept("   ");
        view.onAsk.accept("Who logged in?");

        assertEquals(List.of("Type a question about the imported data first.", "Import a file first"), view.errors);
        assertNull(view.answer);
        assertEquals(List.of(true, false), view.busy);
    }
}
