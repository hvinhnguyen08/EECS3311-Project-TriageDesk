package ca.yorku.triagedesk.casemgmt;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ca.yorku.triagedesk.domain.Case;
import ca.yorku.triagedesk.domain.Finding;
import ca.yorku.triagedesk.domain.SecurityEvent;
import ca.yorku.triagedesk.domain.Severity;
import ca.yorku.triagedesk.domain.Verdict;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import org.junit.jupiter.api.Test;

class CaseStateTest {

    private static final Clock CLOCK = Clock.fixed(Instant.parse("2026-10-30T12:00:00Z"), ZoneOffset.UTC);

    private static Case newCase() {
        SecurityEvent e = SecurityEvent.builder("e1", "t", Instant.parse("2026-10-28T09:00:00Z")).build();
        Finding f = new Finding("d", "t", Severity.HIGH, "203.0.113.7", null, null, null, null, null, List.of(e));
        return new Case("CASE-0001", "t", List.of(f), CLOCK);
    }

    private static String lastHistory(Case c) {
        return c.getHistory().get(c.getHistory().size() - 1);
    }

    @Test
    void normalLifecycleNewInvestigatingEscalatedClosedReopened() {
        Case c = newCase();
        assertEquals("NEW", c.getState().name());

        c.startInvestigation();
        assertInstanceOf(InvestigatingState.class, c.getState());

        c.escalate("Successful login after brute force");
        assertInstanceOf(EscalatedState.class, c.getState());
        assertTrue(lastHistory(c).endsWith("Escalated: Successful login after brute force"));

        c.close("true positive", "Account disabled, keys removed");
        assertInstanceOf(ClosedState.class, c.getState());
        assertTrue(c.isClosed());
        assertEquals(Verdict.TRUE_POSITIVE, c.getResolution());
        assertTrue(lastHistory(c).endsWith("Closed as TRUE_POSITIVE: Account disabled, keys removed"));

        c.reopen();
        assertInstanceOf(InvestigatingState.class, c.getState());
        assertNull(c.getResolution());
        assertFalse(c.isClosed());
    }

    @Test
    void aNewCaseCanBeClosedDirectlyAsAFalsePositive() {
        Case c = newCase();

        c.close("false_positive", "Scheduled vulnerability scan");

        assertTrue(c.isClosed());
        assertEquals(Verdict.FALSE_POSITIVE, c.getResolution());
    }

    @Test
    void disallowedActionsAreRefusedAndListTheAllowedOnes() {
        Case c = newCase();
        InvalidTransitionException e = assertThrows(InvalidTransitionException.class, () -> c.escalate("x"));
        assertEquals("Cannot escalate a case that is NEW. Allowed: start, close", e.getMessage());
        assertThrows(InvalidTransitionException.class, c::reopen);

        c.startInvestigation();
        assertThrows(InvalidTransitionException.class, c::startInvestigation);
        assertThrows(InvalidTransitionException.class, c::reopen);

        c.escalate("needs L2");
        assertThrows(InvalidTransitionException.class, () -> c.escalate("again"));
        assertThrows(InvalidTransitionException.class, c::startInvestigation);
        assertThrows(InvalidTransitionException.class, c::reopen);

        c.close("benign", "Expected admin activity");
        assertThrows(InvalidTransitionException.class, () -> c.escalate("x"));
        assertThrows(InvalidTransitionException.class, () -> c.close("benign", "again"));
        assertThrows(InvalidTransitionException.class, c::startInvestigation);
    }

    @Test
    void refusedActionsLeaveTheCaseUnchanged() {
        Case c = newCase();
        c.startInvestigation();
        int historySize = c.getHistory().size();

        assertThrows(IllegalArgumentException.class, () -> c.escalate("  "));
        assertThrows(IllegalArgumentException.class, () -> c.close("false_positive", ""));
        assertThrows(IllegalArgumentException.class, () -> c.close("needs review", "unsure"));
        assertThrows(IllegalArgumentException.class, () -> c.close("maybe", "unsure"));

        assertInstanceOf(InvestigatingState.class, c.getState());
        assertNull(c.getResolution());
        assertEquals(historySize, c.getHistory().size());
    }

    @Test
    void stateAndResolutionSurviveASnapshot() {
        Case c = newCase();
        c.close("false_positive", "noise");

        Case restored = Case.fromSnapshot(c.snapshot(), CLOCK);

        assertInstanceOf(ClosedState.class, restored.getState());
        assertEquals(Verdict.FALSE_POSITIVE, restored.getResolution());
        assertEquals(c.snapshot(), restored.snapshot());
    }

    @Test
    void fromNameDefaultsToNew() {
        assertInstanceOf(NewState.class, CaseState.fromName(null));
        assertInstanceOf(NewState.class, CaseState.fromName("SOMETHING"));
        assertInstanceOf(EscalatedState.class, CaseState.fromName("ESCALATED"));
    }
}
