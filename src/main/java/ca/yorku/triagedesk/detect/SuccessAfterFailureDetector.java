package ca.yorku.triagedesk.detect;

import ca.yorku.triagedesk.domain.Finding;
import ca.yorku.triagedesk.domain.SecurityEvent;
import ca.yorku.triagedesk.domain.Severity;
import ca.yorku.triagedesk.ingest.WazuhAlertParser;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * A successful login from a source IP that failed to log in several times shortly before
 * (default: 5 failures in the previous 10 minutes). This often means a guessed password.
 */
public class SuccessAfterFailureDetector implements Detector {

    public static final String NAME = "success_after_failure";
    static final List<String> TECHNIQUES = List.of("T1110", "T1078");

    private final int minFailures;
    private final Duration window;

    public SuccessAfterFailureDetector(int minFailures, Duration window) {
        this.minFailures = minFailures;
        this.window = window;
    }

    @Override
    public String name() {
        return NAME;
    }

    @Override
    public List<Finding> detect(List<SecurityEvent> events) {
        Map<String, List<SecurityEvent>> authByIp = DetectorSupport.bySourceIp(events,
                e -> !WazuhAlertParser.SOURCE.equals(e.source())
                        && (SecurityEvent.AUTH_FAILURE.equals(e.category()) || SecurityEvent.AUTH_SUCCESS.equals(e.category())));

        List<Finding> findings = new ArrayList<>();
        authByIp.forEach((ip, auth) -> {
            for (SecurityEvent success : auth) {
                if (!SecurityEvent.AUTH_SUCCESS.equals(success.category())) {
                    continue;
                }
                Instant from = success.timestamp().minus(window);
                List<SecurityEvent> failures = auth.stream()
                        .filter(e -> SecurityEvent.AUTH_FAILURE.equals(e.category()))
                        .filter(e -> !e.timestamp().isBefore(from) && e.timestamp().isBefore(success.timestamp()))
                        .toList();
                if (failures.size() < minFailures) {
                    continue;
                }
                List<SecurityEvent> evidence = new ArrayList<>(failures);
                evidence.add(success);
                String account = success.user() != null ? success.user() : "unknown account";
                String title = "Successful login as " + account + " from " + ip + " after "
                        + failures.size() + " failed attempts";
                findings.add(new Finding(NAME, title, Severity.HIGH, ip, success.host(), success.user(),
                        TECHNIQUES, null, null, evidence));
            }
        });
        return findings;
    }
}
