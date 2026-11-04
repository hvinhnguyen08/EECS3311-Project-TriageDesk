package ca.yorku.triagedesk.gui;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import ca.yorku.triagedesk.agent.LlmReply;
import ca.yorku.triagedesk.agent.MockLlmClient;
import ca.yorku.triagedesk.config.AppConfig;
import ca.yorku.triagedesk.domain.AgentResult;
import ca.yorku.triagedesk.facade.SocAssistant;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import javafx.scene.Parent;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Renders the main screen with the sample data (run with -Dgui.snapshots=true). */
class MainViewSnapshotTest {

    @TempDir
    Path dataDir;

    @Test
    void mainScreenWithSampleData() throws Exception {
        assumeTrue(GuiSnapshots.ENABLED, "set -Dgui.snapshots=true to render GUI screenshots");
        SocAssistant assistant = SocAssistant.create(AppConfig.load(null, Map.of()), dataDir,
                new MockLlmClient(LlmReply.text("unused")));
        assistant.importFile(Path.of("samples/alerts.json"));
        assistant.importFile(Path.of("samples/auth.log"));
        assistant.importFile(Path.of("samples/access.log"));
        assistant.runDetections();

        Path png = GuiSnapshots.save("main", () -> {
            MainViewFx view = new MainViewFx("AI: openai-compatible gpt-4o-mini at api.openai.com");
            view.showFiles(assistant.listBatches());
            view.showCases(assistant.listCases());
            view.showSummary("auth.log", new AgentResult("The file contains 35 events from web01. 203.0.113.7 failed to"
                    + " log in 13 times and then logged in as deploy at 09:17:05.", List.of(
                    "count_by {\"field\":\"srcIp\"} -> {\"203.0.113.7\":16}",
                    "search_events {\"category\":\"auth_success\"} -> {\"total\":3}"), false));
            view.showMessage("8 findings; 3 case(s) created or updated.");
            return (Parent) view.getRoot();
        }, 1200, 760);

        assertTrue(Files.size(png) > 10_000);
    }
}
