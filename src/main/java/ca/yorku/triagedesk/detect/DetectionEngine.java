package ca.yorku.triagedesk.detect;

import ca.yorku.triagedesk.config.AppConfig;
import ca.yorku.triagedesk.domain.Finding;
import ca.yorku.triagedesk.domain.SecurityEvent;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;

/**
 * Context of the Strategy pattern: runs every registered Detector over the events and
 * collects their findings. A detector that throws is skipped and the others still run;
 * its error is available from {@link #getLastErrors()}.
 */
public class DetectionEngine {

    private final List<Detector> detectors = new ArrayList<>();
    private final List<String> lastErrors = new ArrayList<>();

    /** The four built-in detectors with the thresholds from the configuration. */
    public static DetectionEngine withStandardDetectors(AppConfig config) {
        DetectionEngine engine = new DetectionEngine();
        engine.register(new WazuhAlertDetector(config.getWazuhMinLevel()));
        engine.register(new BruteForceDetector(config.getBruteForceThreshold(), config.getBruteForceWindow()));
        engine.register(new SuccessAfterFailureDetector(
                config.getSuccessAfterFailureMinFailures(), config.getSuccessAfterFailureWindow()));
        engine.register(new WebScanDetector(config.getWebScanThreshold(), config.getWebScanWindow()));
        return engine;
    }

    public void register(Detector d) {
        detectors.add(Objects.requireNonNull(d, "detector"));
    }

    /** Runs all detectors; findings are returned oldest first. */
    public List<Finding> runAll(List<SecurityEvent> events) {
        lastErrors.clear();
        List<Finding> findings = new ArrayList<>();
        if (events == null || events.isEmpty()) {
            return findings;
        }
        for (Detector d : detectors) {
            try {
                findings.addAll(d.detect(events));
            } catch (RuntimeException e) {
                lastErrors.add(d.name() + " failed: " + e.getMessage());
            }
        }
        findings.sort(Comparator.comparing(Finding::firstSeen).thenComparing(Finding::detector));
        return findings;
    }

    public List<Detector> getDetectors() {
        return List.copyOf(detectors);
    }

    /** Errors from the detectors that failed during the last {@link #runAll} call. */
    public List<String> getLastErrors() {
        return List.copyOf(lastErrors);
    }
}
