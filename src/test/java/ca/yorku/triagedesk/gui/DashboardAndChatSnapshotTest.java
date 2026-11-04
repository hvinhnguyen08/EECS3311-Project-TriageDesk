package ca.yorku.triagedesk.gui;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import ca.yorku.triagedesk.agent.MockLlmClient;
import ca.yorku.triagedesk.config.AppConfig;
import ca.yorku.triagedesk.domain.AgentResult;
import ca.yorku.triagedesk.domain.DashboardStats;
import ca.yorku.triagedesk.facade.SocAssistant;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import javafx.scene.Parent;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Renders the dashboard and the chat with the sample data (run with -Dgui.snapshots=true). */
class DashboardAndChatSnapshotTest {

    @TempDir
    Path dataDir;

    @Test
    void dashboardAndChat() throws Exception {
        assumeTrue(GuiSnapshots.ENABLED, "set -Dgui.snapshots=true to render GUI screenshots");
        SocAssistant assistant = SocAssistant.create(AppConfig.load(null, Map.of()), dataDir, new MockLlmClient());
        assistant.importFile(Path.of("samples/alerts.json"));
        assistant.importFile(Path.of("samples/auth.log"));
        assistant.importFile(Path.of("samples/access.log"));
        assistant.runDetections();
        assistant.changeStatus("CASE-0002", "close", "true_positive", "Scanner blocked");
        DashboardStats stats = assistant.getDashboardStats();
        List<String> files = assistant.listBatches();

        Path dashboard = GuiSnapshots.save("dashboard", () -> {
            DashboardViewFx view = new DashboardViewFx();
            view.render(stats, files);
            return (Parent) view.getRoot();
        }, 1200, 760);
        Path emptyDashboard = GuiSnapshots.save("dashboard-empty", () -> {
            DashboardViewFx view = new DashboardViewFx();
            view.render(new DashboardStats(0, Map.of(), Map.of(), Map.of("NEW", 0)), List.of());
            return (Parent) view.getRoot();
        }, 900, 500);
        Path chat = GuiSnapshots.save("chat", () -> {
            ChatViewFx view = new ChatViewFx();
            view.showAnswer(ChatViewFx.EXAMPLES.get(0), new AgentResult("The IP 203.0.113.7 failed SSH login 13 times"
                    + " between 09:14:02 and 09:16:33 and then logged in successfully as deploy at 09:17:05. No other IP"
                    + " failed more than 10 times.", List.of(
                    "count_by {\"field\":\"srcIp\",\"category\":\"auth_failure\"} -> {\"203.0.113.7\":13,...}",
                    "search_events {\"srcIp\":\"203.0.113.7\",\"category\":\"auth_success\"} -> {\"total\":1,...}"), false),
                    "2 model call(s), 1666 + 194 tokens");
            return (Parent) view.getRoot();
        }, 1200, 600);

        for (Path p : List.of(dashboard, emptyDashboard, chat)) {
            assertTrue(Files.size(p) > 5_000, p.toString());
        }
    }
}
