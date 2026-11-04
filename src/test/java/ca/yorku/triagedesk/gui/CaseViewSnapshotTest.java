package ca.yorku.triagedesk.gui;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import ca.yorku.triagedesk.agent.LlmReply;
import ca.yorku.triagedesk.agent.MockLlmClient;
import ca.yorku.triagedesk.config.AppConfig;
import ca.yorku.triagedesk.domain.Case;
import ca.yorku.triagedesk.facade.SocAssistant;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import javafx.scene.Parent;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Renders a fully worked case (run with -Dgui.snapshots=true). */
class CaseViewSnapshotTest {

    @TempDir
    Path dataDir;

    @Test
    void caseScreenWithVerdictPlanAndIntel() throws Exception {
        assumeTrue(GuiSnapshots.ENABLED, "set -Dgui.snapshots=true to render GUI screenshots");
        SocAssistant assistant = SocAssistant.create(AppConfig.load(null, Map.of()), dataDir, new MockLlmClient(
                LlmReply.text("{\"verdict\":\"TRUE_POSITIVE\",\"confidence\":0.9,\"reasoning\":\"13 failed logins from"
                        + " 203.0.113.7 were followed by a successful login as deploy at 09:17:05, a denied sudo at 09:17:41"
                        + " and a change to /home/deploy/.ssh/authorized_keys at 09:21:13.\"}"),
                LlmReply.text("{\"steps\":[{\"action\":\"Block 203.0.113.7 at the firewall\",\"reason\":\"source of the brute force\"},"
                        + "{\"action\":\"Disable the deploy account on web01\",\"reason\":\"logged in after 13 failures\"},"
                        + "{\"action\":\"Remove unknown keys from /home/deploy/.ssh/authorized_keys\",\"reason\":\"modified after the login\"}]}")));
        assistant.importFile(Path.of("samples/alerts.json"));
        assistant.importFile(Path.of("samples/auth.log"));
        assistant.runDetections();
        assistant.triageCase("CASE-0001");
        assistant.recommendResponse("CASE-0001");
        assistant.markStepDone("CASE-0001", 1);
        assistant.enrichIocs("CASE-0001");
        assistant.mapAttack("CASE-0001", false);
        assistant.addNote("CASE-0001", "Called the owner of web01; deploy is a CI account.");
        Case c = assistant.getCase("CASE-0001");

        Path png = GuiSnapshots.save("case", () -> {
            CaseViewFx view = new CaseViewFx(p -> { });
            view.render(c);
            view.showMessage("AI verdict: TRUE_POSITIVE (confidence 0.90), 0 tool calls.");
            return (Parent) view.getRoot();
        }, 1280, 800);

        assertTrue(Files.size(png) > 10_000);
    }
}
