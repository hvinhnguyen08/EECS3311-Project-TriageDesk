package ca.yorku.triagedesk.detect;

import static ca.yorku.triagedesk.detect.TestEvents.web;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ca.yorku.triagedesk.domain.Finding;
import ca.yorku.triagedesk.domain.SecurityEvent;
import ca.yorku.triagedesk.domain.Severity;
import ca.yorku.triagedesk.testutil.SampleData;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

class WebScanDetectorTest {

    private final WebScanDetector detector = new WebScanDetector(30, Duration.ofMinutes(2));

    @Test
    void manyNotFoundResponsesFromOneIpIsAScan() {
        List<SecurityEvent> events = new ArrayList<>();
        for (int i = 0; i < 30; i++) {
            events.add(web("198.51.100.23", "404", i * 2));
        }

        List<Finding> findings = detector.detect(events);

        assertEquals(1, findings.size());
        assertEquals(Severity.MEDIUM, findings.get(0).severity());
        assertEquals(List.of("T1595.003"), findings.get(0).techniqueIds());
        assertTrue(findings.get(0).title().contains("gobuster/3.6"));
    }

    @Test
    void otherStatusCodesDoNotCount() {
        List<SecurityEvent> events = new ArrayList<>();
        for (int i = 0; i < 29; i++) {
            events.add(web("198.51.100.23", "404", i));
        }
        for (int i = 0; i < 20; i++) {
            events.add(web("198.51.100.23", "200", i));
        }

        assertEquals(0, detector.detect(events).size());
    }

    @Test
    void sampleAccessLogContainsOneScan() {
        List<Finding> findings = detector.detect(SampleData.accessLog());

        assertEquals(1, findings.size());
        Finding f = findings.get(0);
        assertEquals("198.51.100.23", f.srcIp());
        assertEquals(37, f.events().size());
        assertTrue(f.title().contains("37 not-found responses in 1m6s"), f.title());
    }
}
