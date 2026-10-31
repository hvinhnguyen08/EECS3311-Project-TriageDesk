package ca.yorku.triagedesk.detect;

import static ca.yorku.triagedesk.detect.TestEvents.auth;
import static ca.yorku.triagedesk.detect.TestEvents.failures;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ca.yorku.triagedesk.domain.Finding;
import ca.yorku.triagedesk.domain.SecurityEvent;
import ca.yorku.triagedesk.testutil.SampleData;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

class SuccessAfterFailureDetectorTest {

    private final SuccessAfterFailureDetector detector = new SuccessAfterFailureDetector(5, Duration.ofMinutes(10));

    @Test
    void successAfterEnoughRecentFailuresIsReported() {
        List<SecurityEvent> events = new ArrayList<>(failures("203.0.113.7", 5, 0, 30));
        events.add(auth(SecurityEvent.AUTH_SUCCESS, "203.0.113.7", "deploy", 300));

        List<Finding> findings = detector.detect(events);

        assertEquals(1, findings.size());
        Finding f = findings.get(0);
        assertEquals("deploy", f.user());
        assertEquals(6, f.events().size());
        assertEquals(SecurityEvent.AUTH_SUCCESS, f.events().get(5).category());
        assertEquals(List.of("T1110", "T1078"), f.techniqueIds());
    }

    @Test
    void tooFewOldOrUnrelatedFailuresAreNotReported() {
        List<SecurityEvent> events = new ArrayList<>();
        events.addAll(failures("203.0.113.7", 4, 0, 10));          // only 4
        events.addAll(failures("198.51.100.44", 5, 0, 10));         // other IP
        events.addAll(failures("203.0.113.7", 5, -3600, 10));       // an hour earlier
        events.add(auth(SecurityEvent.AUTH_SUCCESS, "203.0.113.7", "deploy", 120));

        assertEquals(0, detector.detect(events).size());
    }

    @Test
    void sampleAuthLogContainsTheCompromisedDeployAccount() {
        List<Finding> findings = detector.detect(SampleData.authLog());

        assertEquals(1, findings.size());
        Finding f = findings.get(0);
        assertEquals("deploy", f.user());
        assertEquals("203.0.113.7", f.srcIp());
        assertTrue(f.title().contains("after 13 failed attempts"), f.title());
    }
}
