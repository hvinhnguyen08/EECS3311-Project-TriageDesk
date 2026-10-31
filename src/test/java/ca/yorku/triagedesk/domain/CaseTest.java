package ca.yorku.triagedesk.domain;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import org.junit.jupiter.api.Test;

class CaseTest {

    private static final Instant T0 = Instant.parse("2026-10-30T12:00:00Z");
    private static final Clock CLOCK = Clock.fixed(T0, ZoneOffset.UTC);

    private static SecurityEvent event(String id, int secondsAfterT0) {
        return SecurityEvent.builder(id, "auth.log", T0.plusSeconds(secondsAfterT0))
                .source("auth").host("web01").user("root").srcIp("203.0.113.7")
                .message("Failed password for root").category(SecurityEvent.AUTH_FAILURE)
                .build();
    }

    private static Finding finding(Severity severity, SecurityEvent... events) {
        return new Finding("test", "Test finding " + severity, severity, "203.0.113.7", "web01", "root",
                List.of("T1110.001"), null, null, List.of(events));
    }

    @Test
    void severityIsHighestOfFindings() {
        Case c = new Case("CASE-1", "SSH activity",
                List.of(finding(Severity.MEDIUM, event("e1", 0))), CLOCK);
        assertEquals(Severity.MEDIUM, c.getSeverity());

        c.addFinding(finding(Severity.HIGH, event("e2", 10)));
        assertEquals(Severity.HIGH, c.getSeverity());

        c.addFinding(finding(Severity.LOW, event("e3", 20)));
        assertEquals(Severity.HIGH, c.getSeverity());
    }

    @Test
    void caseNeedsAtLeastOneFinding() {
        assertThrows(IllegalArgumentException.class, () -> new Case("CASE-1", "x", List.of(), CLOCK));
    }

    @Test
    void eventsAreDeduplicatedAndSortedByTime() {
        SecurityEvent shared = event("e1", 30);
        Case c = new Case("CASE-1", "x", List.of(
                finding(Severity.LOW, shared, event("e2", 5)),
                finding(Severity.LOW, shared)), CLOCK);

        List<SecurityEvent> events = c.getEvents();

        assertEquals(List.of("e2", "e1"), events.stream().map(SecurityEvent::id).toList());
    }

    @Test
    void notesAreTimestampedAndEmptyNotesRejected() {
        Case c = new Case("CASE-1", "x", List.of(finding(Severity.LOW, event("e1", 0))), CLOCK);

        c.addNote("  Checked with the server owner  ");

        assertEquals(List.of("[2026-10-30T12:00:00Z] Checked with the server owner"), c.getNotes());
        assertThrows(IllegalArgumentException.class, () -> c.addNote("   "));
        assertEquals(1, c.getNotes().size());
    }

    @Test
    void changesAreRecordedInHistory() {
        Case c = new Case("CASE-1", "x", List.of(finding(Severity.LOW, event("e1", 0))), CLOCK);

        c.setVerdict(new TriageVerdict(Verdict.TRUE_POSITIVE, 0.9, "many failures", List.of()));
        c.setResponsePlan(new ResponsePlan(List.of("Block 203.0.113.7")));

        List<String> history = c.getHistory();
        assertEquals(3, history.size());
        assertTrue(history.get(1).contains("TRUE_POSITIVE"));
        assertTrue(history.get(2).contains("1 steps"));
    }
}
