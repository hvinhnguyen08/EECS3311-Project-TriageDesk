package ca.yorku.triagedesk.attack;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ca.yorku.triagedesk.domain.AttackTechnique;
import ca.yorku.triagedesk.domain.Case;
import ca.yorku.triagedesk.domain.Finding;
import ca.yorku.triagedesk.domain.SecurityEvent;
import ca.yorku.triagedesk.domain.Severity;
import ca.yorku.triagedesk.testutil.SampleData;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;
import org.junit.jupiter.api.Test;

class AttackMapperTest {

    private static final AttackMapper MAPPER = AttackMapper.loadBundled();

    private static Case caseWith(String... techniqueIds) {
        SecurityEvent e = SecurityEvent.builder("e1", "b", Instant.parse("2026-10-28T09:00:00Z")).build();
        Finding f = new Finding("d", "t", Severity.HIGH, "203.0.113.7", "web01", null, List.of(techniqueIds), null, null, List.of(e));
        return new Case("CASE-0001", "t", List.of(f));
    }

    private static Function<Case, List<String>> suggests(List<String> calls, String... ids) {
        return c -> {
            calls.add(c.getId());
            return List.of(ids);
        };
    }

    @Test
    void catalogueCoversEverySampleTechnique() {
        assertTrue(MAPPER.size() > 90);
        for (SecurityEvent e : SampleData.all()) {
            for (String id : e.mitreIds()) {
                assertTrue(MAPPER.find(id) != null, "missing " + id);
            }
        }
        for (String id : List.of("T1110.001", "T1595.003", "T1078", "T1098.004", "T1548.003")) {
            assertTrue(MAPPER.find(id) != null, "missing " + id);
        }
        AttackTechnique t = MAPPER.find(" t1110.001 ");
        assertEquals("Password Guessing", t.name());
        assertEquals("Credential Access", t.tactic());
        assertEquals("Defense Evasion, Persistence, Privilege Escalation, Initial Access", MAPPER.find("T1078").tactic());
        assertNull(MAPPER.find("T9999"));
    }

    @Test
    void detectionIdsAreUsedWithoutAskingTheAgent() {
        List<String> calls = new ArrayList<>();

        MappingResult r = MAPPER.map(caseWith("T1110.001", "T1110", "T1110.001"), false, suggests(calls, "T1078"));

        assertEquals(List.of("T1110.001", "T1110"), r.techniques().stream().map(AttackTechnique::id).toList());
        assertEquals(List.of("T1110.001", "T1110"), r.fromDetections());
        assertEquals(List.of(), r.fromAgent());
        assertEquals(List.of(), calls, "the agent was not asked");
        assertEquals("detection", r.sourceOf("T1110"));
    }

    @Test
    void agentIsAskedWhenThereAreNoIdsAndInventedIdsAreDropped() {
        List<String> calls = new ArrayList<>();

        MappingResult r = MAPPER.map(caseWith(), false, suggests(calls, "T1098.004", "T9999.123", "t1548.003"));

        assertEquals(List.of("CASE-0001"), calls);
        assertEquals(List.of("T1098.004", "T1548.003"), r.fromAgent());
        assertEquals(List.of("T9999.123"), r.rejected());
        assertEquals("AI", r.sourceOf("T1098.004"));
    }

    @Test
    void askAgentAddsToTheDetectionsWithoutDuplicates() {
        MappingResult r = MAPPER.map(caseWith("T1110.001", "T0000"), true, suggests(new ArrayList<>(), "T1110.001", "T1098.004"));

        assertEquals(List.of("T1110.001", "T1098.004"), r.techniques().stream().map(AttackTechnique::id).toList());
        assertEquals(List.of("T1098.004"), r.fromAgent());
        assertEquals(List.of("T0000"), r.rejected());
    }

    @Test
    void noIdsAndNoAgentMeansNoMappingAvailable() {
        Function<Case, List<String>> failing = c -> {
            throw new IllegalStateException("AI service unavailable");
        };

        IllegalStateException e = assertThrows(IllegalStateException.class, () -> MAPPER.map(caseWith(), false, failing));
        assertTrue(e.getMessage().startsWith("No mapping available"));

        assertThrows(IllegalStateException.class, () -> MAPPER.map(caseWith("T1110"), true, failing),
                "an explicit --ai request reports the failure");
    }
}
