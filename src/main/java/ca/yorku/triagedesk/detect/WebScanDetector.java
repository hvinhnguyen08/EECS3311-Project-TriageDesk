package ca.yorku.triagedesk.detect;

import ca.yorku.triagedesk.domain.Finding;
import ca.yorku.triagedesk.domain.SecurityEvent;
import ca.yorku.triagedesk.domain.Severity;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Web directory scan: many "404 Not Found" responses to one source IP in a short time
 * (default: 30 in 2 minutes), typical of wordlist tools such as gobuster or dirb.
 */
public class WebScanDetector implements Detector {

    public static final String NAME = "web_scan";
    static final String TECHNIQUE = "T1595.003";

    private final int notFoundThreshold;
    private final Duration window;

    public WebScanDetector(int notFoundThreshold, Duration window) {
        if (notFoundThreshold < 2) {
            throw new IllegalArgumentException("notFoundThreshold must be at least 2");
        }
        this.notFoundThreshold = notFoundThreshold;
        this.window = window;
    }

    @Override
    public String name() {
        return NAME;
    }

    @Override
    public List<Finding> detect(List<SecurityEvent> events) {
        Map<String, List<SecurityEvent>> notFoundByIp = DetectorSupport.bySourceIp(events,
                e -> SecurityEvent.WEB_REQUEST.equals(e.category()) && "404".equals(e.attribute("status")));

        List<Finding> findings = new ArrayList<>();
        notFoundByIp.forEach((ip, notFound) -> {
            for (List<SecurityEvent> burst : DetectorSupport.bursts(notFound, notFoundThreshold, window)) {
                String agent = DetectorSupport.common(burst, e -> e.attribute("userAgent"));
                String title = "Web directory scan from " + ip + ": " + burst.size() + " not-found responses in "
                        + DetectorSupport.format(DetectorSupport.span(burst))
                        + (agent != null ? " (user agent " + agent + ")" : "");
                findings.add(new Finding(NAME, title, Severity.MEDIUM, ip,
                        DetectorSupport.common(burst, SecurityEvent::host), null,
                        List.of(TECHNIQUE), null, null, burst));
            }
        });
        return findings;
    }
}
