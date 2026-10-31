package ca.yorku.triagedesk.casemgmt;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ca.yorku.triagedesk.config.AppConfig;
import ca.yorku.triagedesk.detect.DetectionEngine;
import ca.yorku.triagedesk.domain.Case;
import ca.yorku.triagedesk.domain.Finding;
import ca.yorku.triagedesk.domain.SecurityEvent;
import ca.yorku.triagedesk.domain.Severity;
import ca.yorku.triagedesk.testutil.SampleData;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class CaseManagerTest {

    private static final Instant T0 = Instant.parse("2026-10-28T09:00:00Z");
    private static final Clock CLOCK = Clock.fixed(Instant.parse("2026-10-30T12:00:00Z"), ZoneOffset.UTC);

    @TempDir
    Path dataDir;

    private CaseManager manager;

    @BeforeEach
    void setUp() {
        manager = new CaseManager(dataDir, CLOCK);
    }

    private static List<Finding> sampleFindings() {
        return DetectionEngine.withStandardDetectors(AppConfig.load(null, Map.of())).runAll(SampleData.all());
    }

    private static int nextEvent;

    private static Finding finding(String detector, Severity severity, String ip, String host, int minutes) {
        SecurityEvent e = SecurityEvent.builder("e" + (++nextEvent), "t", T0.plusSeconds(60L * minutes))
                .srcIp(ip).host(host).build();
        return new Finding(detector, detector + " at +" + minutes + "m", severity, ip, host, null,
                List.of(), null, null, List.of(e));
    }

    @Test
    void sampleFindingsBecomeThreePrioritisedCases() {
        List<Case> cases = manager.createCases(sampleFindings());

        assertEquals(3, cases.size());
        Case ssh = cases.get(0);
        Case rootkit = cases.get(1);
        Case web = cases.get(2);

        assertEquals("CASE-0001", ssh.getId());
        assertEquals(4, ssh.getFindings().size(), "brute force, Wazuh 5763, successful login, authorized_keys change");
        assertEquals(Severity.HIGH, ssh.getSeverity());
        assertEquals(80, ssh.getPriority());
        assertTrue(ssh.getTitle().contains("(+3 related)"), ssh.getTitle());

        assertEquals("CASE-0003", rootkit.getId());
        assertEquals(Severity.CRITICAL, rootkit.getSeverity());
        assertEquals(80, rootkit.getPriority());

        assertEquals("CASE-0002", web.getId());
        assertEquals(3, web.getFindings().size());
        assertEquals(75, web.getPriority());
        assertEquals(cases, manager.listCases());
    }

    @Test
    void runningDetectionsAgainChangesNothing() {
        manager.createCases(sampleFindings());

        List<Case> again = manager.createCases(sampleFindings());

        assertEquals(List.of(), again);
        assertEquals(3, manager.listCases().size());
        assertEquals(4, manager.getCase("CASE-0001").getFindings().size());
    }

    @Test
    void casesSurviveARestartAndIdsContinue() {
        manager.createCases(sampleFindings());

        CaseManager reloaded = new CaseManager(dataDir, CLOCK);
        reloaded.load();

        assertEquals(manager.listCases().stream().map(Case::snapshot).toList(),
                reloaded.listCases().stream().map(Case::snapshot).toList());
        List<Case> created = reloaded.createCases(List.of(finding("x", Severity.LOW, "192.0.2.9", null, 0)));
        assertEquals("CASE-0004", created.get(0).getId());
        assertEquals(List.of(), reloaded.getWarnings());
    }

    @Test
    void relatedFindingJoinsTheExistingCaseUnlessItIsTooLate() {
        manager.createCases(List.of(finding("a", Severity.MEDIUM, "203.0.113.7", "web01", 0)));

        List<Case> joined = manager.createCases(List.of(finding("b", Severity.HIGH, "203.0.113.7", null, 59)));
        List<Case> separate = manager.createCases(List.of(finding("c", Severity.LOW, "203.0.113.7", null, 59 + 61)));

        assertEquals("CASE-0001", joined.get(0).getId());
        assertEquals(2, joined.get(0).getFindings().size());
        assertEquals(Severity.HIGH, joined.get(0).getSeverity());
        assertEquals("CASE-0002", separate.get(0).getId());
    }

    @Test
    void groupingUsesTheIpFirstAndTheHostOnlyWithoutAnIp() {
        List<Case> cases = manager.createCases(List.of(
                finding("a", Severity.LOW, "203.0.113.7", "web01", 0),
                finding("b", Severity.LOW, "198.51.100.23", "web01", 5),   // other IP, same host: separate
                finding("c", Severity.LOW, null, "web01", 10),             // no IP: joins by host (first match)
                finding("d", Severity.LOW, null, null, 10)));              // nothing to group by

        assertEquals(3, cases.size());
        assertEquals(2, manager.getCase("CASE-0001").getFindings().size());
        assertEquals(1, manager.getCase("CASE-0002").getFindings().size());
        assertEquals(1, manager.getCase("CASE-0003").getFindings().size());
    }

    @Test
    void priorityFormula() {
        Case single = new Case("CASE-9", "t", List.of(finding("a", Severity.MEDIUM, "x", null, 0)), CLOCK);
        Case many = new Case("CASE-9", "t", List.of(
                finding("a", Severity.CRITICAL, "x", null, 0),
                finding("b", Severity.LOW, "x", null, 1),
                finding("a", Severity.LOW, "x", null, 2),
                finding("a", Severity.LOW, "x", null, 3),
                finding("a", Severity.LOW, "x", null, 4)), CLOCK);

        assertEquals(40, CaseManager.computePriority(single));
        assertEquals(100, CaseManager.computePriority(many));
    }

    @Test
    void unknownCaseIdIsRejectedAndIdsAreCaseInsensitive() {
        manager.createCases(List.of(finding("a", Severity.LOW, "203.0.113.7", null, 0)));

        assertEquals("CASE-0001", manager.getCase(" case-0001 ").getId());
        assertThrows(IllegalArgumentException.class, () -> manager.getCase("CASE-0099"));
        assertThrows(IllegalArgumentException.class, () -> manager.getCase(null));
    }

    @Test
    void saveFailureKeepsTheCaseInMemoryWithAWarning() throws IOException {
        Path notADirectory = Files.createFile(dataDir.resolve("blocked"));
        CaseManager blocked = new CaseManager(notADirectory, CLOCK);

        List<Case> cases = blocked.createCases(List.of(finding("a", Severity.LOW, "203.0.113.7", null, 0)));

        assertEquals(1, cases.size());
        assertEquals(1, blocked.listCases().size());
        assertEquals(1, blocked.getWarnings().size());
        assertTrue(blocked.getWarnings().get(0).contains("kept in memory"));
    }

    @Test
    void corruptCaseFilesAreSkippedOnLoad() throws IOException {
        manager.createCases(List.of(finding("a", Severity.LOW, "203.0.113.7", null, 0)));
        Files.writeString(dataDir.resolve("cases").resolve("CASE-0002.json"), "{ broken");

        CaseManager reloaded = new CaseManager(dataDir, CLOCK);
        reloaded.load();

        assertEquals(1, reloaded.listCases().size());
        assertEquals(1, reloaded.getWarnings().size());
        assertFalse(reloaded.getWarnings().get(0).isEmpty());
    }
}
