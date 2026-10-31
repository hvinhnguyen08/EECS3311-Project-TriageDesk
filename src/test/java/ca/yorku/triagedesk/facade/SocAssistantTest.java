package ca.yorku.triagedesk.facade;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import ca.yorku.triagedesk.config.AppConfig;
import ca.yorku.triagedesk.domain.Case;
import ca.yorku.triagedesk.domain.DashboardStats;
import ca.yorku.triagedesk.ingest.UnsupportedFormatException;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class SocAssistantTest {

    private static final AppConfig CONFIG = AppConfig.load(null, Map.of());

    @TempDir
    Path dataDir;

    private SocAssistant assistant;

    @BeforeEach
    void setUp() {
        assistant = SocAssistant.create(CONFIG, dataDir);
    }

    private void importSamples() {
        assistant.importFile(Path.of("samples/alerts.json"));
        assistant.importFile(Path.of("samples/auth.log"));
        assistant.importFile(Path.of("samples/access.log"));
    }

    @Test
    void importReportsFormatAndCounts() {
        assertEquals(new ImportResult("alerts.json", "wazuh", 12, 0), assistant.importFile(Path.of("samples/alerts.json")));
        assertEquals(new ImportResult("auth.log", "auth", 35, 0), assistant.importFile(Path.of("samples/auth.log")));
        assertEquals(new ImportResult("access.log", "apache", 51, 0), assistant.importFile(Path.of("samples/access.log")));
        assertEquals(new ImportResult("alerts-with-bad-lines.json", "wazuh", 2, 3),
                assistant.importFile(Path.of("samples/errors/alerts-with-bad-lines.json")));
        assertEquals(List.of("alerts.json", "auth.log", "access.log", "alerts-with-bad-lines.json"), assistant.listBatches());
    }

    @Test
    void authLogTimesAreReadAsUtcByDefault() {
        assistant.importFile(Path.of("samples/auth.log"));

        Case c = null;
        assistant.runDetections();
        for (Case each : assistant.listCases()) {
            if (each.getFindings().get(0).detector().equals("brute_force")) {
                c = each;
            }
        }
        assertEquals(Instant.parse("2026-10-28T09:14:02Z"), c.getFindings().get(0).firstSeen());
    }

    @Test
    void importErrors() {
        assertThrows(UnsupportedFormatException.class,
                () -> assistant.importFile(Path.of("samples/errors/unsupported-format.txt")));
        IllegalArgumentException missing = assertThrows(IllegalArgumentException.class,
                () -> assistant.importFile(Path.of("samples/nope.log")));
        assertEquals("File not found: " + Path.of("samples/nope.log"), missing.getMessage());
        assertEquals(List.of(), assistant.listBatches());
    }

    @Test
    void detectionsNeedImportedEvents() {
        IllegalStateException e = assertThrows(IllegalStateException.class, () -> assistant.runDetections());
        assertEquals("Import a file first", e.getMessage());
    }

    @Test
    void fullDeterministicWorkflowSurvivesRestarts() {
        importSamples();
        DetectionResult first = assistant.runDetections();
        assertEquals(8, first.findings());
        assertEquals(3, first.cases().size());
        assertEquals(List.of(), first.warnings());

        SocAssistant restarted = SocAssistant.create(CONFIG, dataDir);
        DetectionResult again = restarted.runDetections();
        assertEquals(8, again.findings());
        assertEquals(0, again.cases().size(), "nothing new on a second run");

        restarted.changeStatus("CASE-0001", "start", null);
        restarted.changeStatus("CASE-0001", "escalate", "deploy account compromised");
        restarted.addNote("CASE-0001", "Disabled the deploy account");
        restarted.changeStatus("CASE-0002", "close", "true_positive", "Scanner blocked at the WAF");

        SocAssistant third = SocAssistant.create(CONFIG, dataDir);
        assertEquals("ESCALATED", third.getCase("CASE-0001").getState().name());
        assertEquals(1, third.getCase("CASE-0001").getNotes().size());
        assertEquals("CLOSED", third.getCase("CASE-0002").getState().name());
    }

    @Test
    void dashboardStats() {
        assertEquals(true, assistant.getDashboardStats().isEmpty());

        importSamples();
        assistant.runDetections();
        DashboardStats s = assistant.getDashboardStats();

        assertEquals(98, s.totalEvents());
        assertEquals(SocAssistant.TOP_N, s.topSourceIps().size());
        assertEquals("198.51.100.23", s.topSourceIps().keySet().iterator().next());
        assertEquals(Map.of("NEW", 3, "INVESTIGATING", 0, "ESCALATED", 0, "CLOSED", 0), s.casesByState());
    }
}
