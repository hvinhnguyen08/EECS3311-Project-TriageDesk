package ca.yorku.triagedesk.detect;

import ca.yorku.triagedesk.domain.Finding;
import ca.yorku.triagedesk.domain.SecurityEvent;
import ca.yorku.triagedesk.domain.Severity;
import ca.yorku.triagedesk.ingest.WazuhAlertParser;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Many failed logins from one source IP in a short time (default: 10 in 5 minutes).
 * Only raw log events are counted: Wazuh already summarises failures in its own
 * brute-force alerts, which WazuhAlertDetector reports.
 */
public class BruteForceDetector implements Detector {

    public static final String NAME = "brute_force";
    static final String TECHNIQUE = "T1110.001";

    private final int threshold;
    private final Duration window;

    public BruteForceDetector(int threshold, Duration window) {
        if (threshold < 2) {
            throw new IllegalArgumentException("threshold must be at least 2");
        }
        this.threshold = threshold;
        this.window = window;
    }

    @Override
    public String name() {
        return NAME;
    }

    @Override
    public List<Finding> detect(List<SecurityEvent> events) {
        Map<String, List<SecurityEvent>> failuresByIp = DetectorSupport.bySourceIp(events,
                e -> SecurityEvent.AUTH_FAILURE.equals(e.category()) && !WazuhAlertParser.SOURCE.equals(e.source()));

        List<Finding> findings = new ArrayList<>();
        failuresByIp.forEach((ip, failures) -> {
            for (List<SecurityEvent> burst : DetectorSupport.bursts(failures, threshold, window)) {
                long users = DetectorSupport.distinct(burst, SecurityEvent::user);
                String title = "Brute force from " + ip + ": " + burst.size() + " failed logins in "
                        + DetectorSupport.format(DetectorSupport.span(burst))
                        + " against " + users + (users == 1 ? " account" : " accounts");
                findings.add(new Finding(NAME, title, Severity.HIGH, ip,
                        DetectorSupport.common(burst, SecurityEvent::host),
                        DetectorSupport.common(burst, SecurityEvent::user),
                        List.of(TECHNIQUE), null, null, burst));
            }
        });
        return findings;
    }
}
