package ca.yorku.triagedesk.detect;

import static ca.yorku.triagedesk.detect.TestEvents.failures;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ca.yorku.triagedesk.domain.Finding;
import ca.yorku.triagedesk.domain.SecurityEvent;
import ca.yorku.triagedesk.domain.Severity;
import ca.yorku.triagedesk.testutil.SampleData;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

class BruteForceDetectorTest {

    private final BruteForceDetector detector = new BruteForceDetector(10, Duration.ofMinutes(5));

    @Test
    void tenFailuresWithinFiveMinutesIsABruteForce() {
        List<Finding> findings = detector.detect(failures("203.0.113.7", 10, 0, 30));

        assertEquals(1, findings.size());
        Finding f = findings.get(0);
        assertEquals("203.0.113.7", f.srcIp());
        assertEquals(Severity.HIGH, f.severity());
        assertEquals(List.of("T1110.001"), f.techniqueIds());
        assertEquals(10, f.events().size());
        assertEquals("root", f.user());
    }

    @Test
    void belowThresholdOrTooSpreadOutIsNot() {
        assertEquals(0, detector.detect(failures("203.0.113.7", 9, 0, 10)).size());
        // 10 failures over 6m40s: no 5-minute window holds 10 of them.
        assertEquals(0, detector.detect(failures("203.0.113.7", 10, 0, 40)).size());
    }

    @Test
    void separateBurstsAndSeparateIpsGiveSeparateFindings() {
        List<SecurityEvent> events = new ArrayList<>(failures("203.0.113.7", 10, 0, 5));
        events.addAll(failures("203.0.113.7", 12, 3600, 5));
        events.addAll(failures("198.51.100.44", 10, 0, 5));

        List<Finding> findings = detector.detect(events);

        assertEquals(3, findings.size());
        assertEquals(List.of(10, 12, 10), findings.stream().map(f -> f.events().size()).toList());
    }

    @Test
    void wazuhAlertsAndEventsWithoutAnIpAreIgnored() {
        List<SecurityEvent> events = new ArrayList<>();
        for (int i = 0; i < 10; i++) {
            events.add(SecurityEvent.builder("w" + i, "alerts.json", TestEvents.T0.plusSeconds(i))
                    .source("wazuh").srcIp("203.0.113.7").category(SecurityEvent.AUTH_FAILURE).build());
            events.add(TestEvents.auth(SecurityEvent.AUTH_FAILURE, null, "root", i));
        }

        assertEquals(0, detector.detect(events).size());
    }

    @Test
    void sampleAuthLogContainsOneBruteForce() {
        List<Finding> findings = detector.detect(SampleData.authLog());

        assertEquals(1, findings.size());
        Finding f = findings.get(0);
        assertEquals("203.0.113.7", f.srcIp());
        assertEquals(13, f.events().size());
        assertEquals("web01", f.host());
        assertNull(f.user(), "several accounts were targeted");
        assertTrue(f.title().contains("13 failed logins in 2m31s against 4 accounts"), f.title());
    }

    @Test
    void thresholdMustBeMeaningful() {
        assertThrows(IllegalArgumentException.class, () -> new BruteForceDetector(1, Duration.ofMinutes(5)));
    }
}
