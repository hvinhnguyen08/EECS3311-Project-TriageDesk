package ca.yorku.triagedesk.domain;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;

class DomainValidationTest {

    @Test
    void verdictParsingIsLenientAndFallsBackToNeedsReview() {
        assertEquals(Verdict.TRUE_POSITIVE, Verdict.parse("true positive"));
        assertEquals(Verdict.FALSE_POSITIVE, Verdict.parse(" False-Positive "));
        assertEquals(Verdict.NEEDS_REVIEW, Verdict.parse("probably bad"));
        assertEquals(Verdict.NEEDS_REVIEW, Verdict.parse(null));
    }

    @Test
    void triageVerdictRejectsConfidenceOutsideZeroToOne() {
        assertThrows(IllegalArgumentException.class,
                () -> new TriageVerdict(Verdict.BENIGN, 1.5, "", List.of()));
        assertThrows(IllegalArgumentException.class,
                () -> new TriageVerdict(Verdict.BENIGN, Double.NaN, "", List.of()));
        assertEquals(Verdict.NEEDS_REVIEW, TriageVerdict.needsReview("raw", List.of()).verdict());
    }

    @Test
    void responsePlanTracksProgress() {
        ResponsePlan plan = new ResponsePlan(List.of("Block IP", "Reset password"));

        plan.markDone(0);
        assertTrue(plan.isDone(0));
        assertFalse(plan.isComplete());

        plan.markDone(1);
        assertTrue(plan.isComplete());
        assertThrows(IndexOutOfBoundsException.class, () -> plan.markDone(2));
        assertThrows(IllegalArgumentException.class, () -> new ResponsePlan(List.of()));
    }

    @Test
    void iocScoreMustBeInRangeOrUnavailable() {
        Ioc ioc = Ioc.unscored(Ioc.IP, "203.0.113.7");
        assertFalse(ioc.isScored());

        Ioc scored = ioc.withScore(87, "AbuseIPDB");
        assertTrue(scored.isScored());
        assertEquals(87, scored.score());
        assertThrows(IllegalArgumentException.class, () -> ioc.withScore(101, "x"));
    }

    @Test
    void attackTechniqueIdMustLookLikeAnAttackId() {
        new AttackTechnique("T1110", "Brute Force", "credential-access");
        new AttackTechnique("T1110.001", "Password Guessing", "credential-access");
        assertThrows(IllegalArgumentException.class, () -> new AttackTechnique("1110", "x", "y"));
    }

    @Test
    void findingComputesTimeRangeFromEvidence() {
        Instant t0 = Instant.parse("2026-10-30T12:00:00Z");
        SecurityEvent a = SecurityEvent.builder("a", "b", t0.plusSeconds(60)).message("m").build();
        SecurityEvent b = SecurityEvent.builder("b", "b", t0).message("m").build();

        Finding f = new Finding("d", "t", Severity.LOW, null, null, null, null, null, null, List.of(a, b));

        assertEquals(t0, f.firstSeen());
        assertEquals(t0.plusSeconds(60), f.lastSeen());
        assertThrows(IllegalArgumentException.class,
                () -> new Finding("d", "t", Severity.LOW, null, null, null, null, null, null, List.of()));
    }

    @Test
    void wazuhLevelsMapToSeverity() {
        assertEquals(Severity.LOW, Severity.fromWazuhLevel(3));
        assertEquals(Severity.MEDIUM, Severity.fromWazuhLevel(7));
        assertEquals(Severity.HIGH, Severity.fromWazuhLevel(10));
        assertEquals(Severity.CRITICAL, Severity.fromWazuhLevel(15));
    }
}
