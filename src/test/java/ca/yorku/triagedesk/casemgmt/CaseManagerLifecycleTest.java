package ca.yorku.triagedesk.casemgmt;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ca.yorku.triagedesk.domain.Case;
import ca.yorku.triagedesk.domain.Finding;
import ca.yorku.triagedesk.domain.SecurityEvent;
import ca.yorku.triagedesk.domain.Severity;
import ca.yorku.triagedesk.domain.TriageVerdict;
import ca.yorku.triagedesk.domain.Verdict;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.Path;

class CaseManagerLifecycleTest {

    private static final Instant T0 = Instant.parse("2026-10-28T09:00:00Z");
    private static final Clock CLOCK = Clock.fixed(Instant.parse("2026-10-30T12:00:00Z"), ZoneOffset.UTC);

    @TempDir
    Path dataDir;

    private CaseManager manager;
    private int nextEvent;

    @BeforeEach
    void setUp() {
        manager = new CaseManager(dataDir, CLOCK);
        manager.createCases(List.of(finding("203.0.113.7", 0)));
    }

    private Finding finding(String ip, int minutes) {
        SecurityEvent e = SecurityEvent.builder("e" + (++nextEvent), "t", T0.plusSeconds(60L * minutes)).srcIp(ip).build();
        return new Finding("d", "finding " + nextEvent, Severity.MEDIUM, ip, null, null, null, null, null, List.of(e));
    }

    private Case reloaded(String id) {
        CaseManager other = new CaseManager(dataDir, CLOCK);
        other.load();
        return other.getCase(id);
    }

    @Test
    void actionsAreAppliedAndSaved() {
        manager.applyAction("CASE-0001", "start", null);
        manager.applyAction("case-0001", " Escalate ", "Possible compromise");

        assertEquals(EscalatedState.NAME, reloaded("CASE-0001").getState().name());

        manager.applyAction("CASE-0001", "close", "true_positive", "Contained");
        Case saved = reloaded("CASE-0001");
        assertEquals(ClosedState.NAME, saved.getState().name());
        assertEquals(Verdict.TRUE_POSITIVE, saved.getResolution());
    }

    @Test
    void refusedActionIsNotSaved() {
        assertThrows(InvalidTransitionException.class, () -> manager.applyAction("CASE-0001", "reopen", null));
        assertThrows(IllegalArgumentException.class, () -> manager.applyAction("CASE-0001", "archive", null));
        assertThrows(IllegalArgumentException.class, () -> manager.applyAction("CASE-0001", "close", "false_positive", " "));

        assertEquals(NewState.NAME, reloaded("CASE-0001").getState().name());
    }

    @Test
    void notesAreSavedAndEmptyNotesRejected() {
        manager.addNote("CASE-0001", "Called the server owner");

        assertEquals(1, reloaded("CASE-0001").getNotes().size());
        assertTrue(reloaded("CASE-0001").getNotes().get(0).endsWith("Called the server owner"));
        assertThrows(IllegalArgumentException.class, () -> manager.addNote("CASE-0001", ""));
    }

    @Test
    void recordingAVerdictStartsTheInvestigationOfANewCaseOnly() {
        TriageVerdict v = new TriageVerdict(Verdict.TRUE_POSITIVE, 0.9, "evidence", List.of("count_by"));

        manager.recordVerdict("CASE-0001", v);
        assertEquals(InvestigatingState.NAME, reloaded("CASE-0001").getState().name());
        assertEquals(v, reloaded("CASE-0001").getVerdict());

        manager.applyAction("CASE-0001", "escalate", "L2 please");
        manager.recordVerdict("CASE-0001", v);
        assertEquals(EscalatedState.NAME, manager.getCase("CASE-0001").getState().name());
    }

    @Test
    void countByStateListsAllStates() {
        manager.createCases(List.of(finding("198.51.100.23", 0), finding("198.51.100.44", 0)));
        manager.applyAction("CASE-0002", "start", null);
        manager.applyAction("CASE-0003", "close", "benign", "test traffic");

        assertEquals(Map.of("NEW", 1, "INVESTIGATING", 1, "ESCALATED", 0, "CLOSED", 1), manager.countByState());
        assertEquals(List.of("NEW", "INVESTIGATING", "ESCALATED", "CLOSED"), List.copyOf(manager.countByState().keySet()));
    }

    @Test
    void newFindingsDoNotJoinAClosedCase() {
        manager.applyAction("CASE-0001", "close", "false_positive", "noise");

        List<Case> created = manager.createCases(List.of(finding("203.0.113.7", 5)));

        assertEquals("CASE-0002", created.get(0).getId());
        assertEquals(1, manager.getCase("CASE-0001").getFindings().size());
    }
}
