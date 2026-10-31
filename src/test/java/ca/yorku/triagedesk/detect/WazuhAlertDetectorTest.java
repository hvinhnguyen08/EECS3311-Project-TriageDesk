package ca.yorku.triagedesk.detect;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ca.yorku.triagedesk.domain.Finding;
import ca.yorku.triagedesk.domain.SecurityEvent;
import ca.yorku.triagedesk.domain.Severity;
import ca.yorku.triagedesk.testutil.SampleData;
import java.util.List;
import org.junit.jupiter.api.Test;

class WazuhAlertDetectorTest {

    private final WazuhAlertDetector detector = new WazuhAlertDetector(7);

    private static SecurityEvent alert(String id, String ruleId, int level, String ip, List<String> mitre) {
        return SecurityEvent.builder(id, "alerts.json", TestEvents.T0)
                .source("wazuh").host("web01").srcIp(ip).ruleId(ruleId).ruleLevel(level)
                .message("rule " + ruleId).mitreIds(mitre).category(SecurityEvent.ALERT).build();
    }

    @Test
    void sampleAlertsAtLevelSevenOrAbove() {
        List<Finding> findings = detector.detect(SampleData.alerts());

        assertEquals(List.of("5763", "550", "31151", "31103", "510"),
                findings.stream().map(f -> f.events().get(0).ruleId()).toList());
        Finding rootkit = findings.get(4);
        assertEquals(Severity.CRITICAL, rootkit.severity());
        assertEquals("db01", rootkit.host());
        assertNull(rootkit.srcIp());
        assertEquals(List.of("T1554"), rootkit.techniqueIds());
    }

    @Test
    void repeatedAlertsForOneRuleAndIpAreMerged() {
        List<Finding> findings = detector.detect(List.of(
                alert("a1", "5763", 10, "203.0.113.7", List.of("T1110")),
                alert("a2", "5763", 12, "203.0.113.7", List.of("T1110", "T1021.004")),
                alert("a3", "5763", 10, "198.51.100.44", List.of("T1110"))));

        assertEquals(2, findings.size());
        Finding merged = findings.get(0);
        assertEquals(2, merged.events().size());
        assertEquals(Severity.CRITICAL, merged.severity(), "highest level wins");
        assertEquals(List.of("T1110", "T1021.004"), merged.techniqueIds());
        assertTrue(merged.title().contains("[2 alerts]"), merged.title());
    }

    @Test
    void lowLevelAlertsAndOtherSourcesAreIgnored() {
        SecurityEvent lowLevel = alert("a1", "5715", 3, "192.168.1.20", List.of());
        SecurityEvent notWazuh = SecurityEvent.builder("x", "auth.log", TestEvents.T0)
                .source("auth").ruleLevel(15).build();

        assertEquals(0, detector.detect(List.of(lowLevel, notWazuh)).size());
    }
}
