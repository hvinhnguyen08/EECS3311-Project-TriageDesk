package ca.yorku.triagedesk.detect;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ca.yorku.triagedesk.config.AppConfig;
import ca.yorku.triagedesk.domain.Finding;
import ca.yorku.triagedesk.domain.SecurityEvent;
import ca.yorku.triagedesk.testutil.SampleData;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class DetectionEngineTest {

    private static final Detector FAILING = new Detector() {
        @Override
        public List<Finding> detect(List<SecurityEvent> events) {
            throw new IllegalStateException("boom");
        }

        @Override
        public String name() {
            return "failing";
        }
    };

    @Test
    void standardDetectorsOnAllSampleFiles() {
        DetectionEngine engine = DetectionEngine.withStandardDetectors(AppConfig.load(null, Map.of()));

        List<Finding> findings = engine.runAll(SampleData.all());

        assertEquals(4, engine.getDetectors().size());
        assertEquals(8, findings.size());
        assertEquals(5, findings.stream().filter(f -> f.detector().equals(WazuhAlertDetector.NAME)).count());
        assertEquals(1, findings.stream().filter(f -> f.detector().equals(BruteForceDetector.NAME)).count());
        assertEquals(1, findings.stream().filter(f -> f.detector().equals(SuccessAfterFailureDetector.NAME)).count());
        assertEquals(1, findings.stream().filter(f -> f.detector().equals(WebScanDetector.NAME)).count());
        for (int i = 1; i < findings.size(); i++) {
            assertTrue(!findings.get(i).firstSeen().isBefore(findings.get(i - 1).firstSeen()), "sorted by time");
        }
        assertEquals(List.of(), engine.getLastErrors());
    }

    @Test
    void aFailingDetectorIsSkippedAndReported() {
        DetectionEngine engine = new DetectionEngine();
        engine.register(FAILING);
        engine.register(new BruteForceDetector(10, Duration.ofMinutes(5)));

        List<Finding> findings = engine.runAll(SampleData.authLog());

        assertEquals(1, findings.size());
        assertEquals(List.of("failing failed: boom"), engine.getLastErrors());
    }

    @Test
    void thresholdsComeFromTheConfiguration() {
        AppConfig strict = AppConfig.load(null, Map.of("DETECT_BRUTE_FORCE_THRESHOLD", "20"));

        List<Finding> findings = DetectionEngine.withStandardDetectors(strict).runAll(SampleData.authLog());

        assertEquals(0, findings.stream().filter(f -> f.detector().equals(BruteForceDetector.NAME)).count());
    }

    @Test
    void noEventsGiveNoFindings() {
        DetectionEngine engine = new DetectionEngine();
        engine.register(FAILING);

        assertEquals(List.of(), engine.runAll(List.of()));
        assertEquals(List.of(), engine.getLastErrors());
    }
}
