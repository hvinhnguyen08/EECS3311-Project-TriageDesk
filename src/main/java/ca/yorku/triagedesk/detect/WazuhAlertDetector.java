package ca.yorku.triagedesk.detect;

import ca.yorku.triagedesk.domain.Finding;
import ca.yorku.triagedesk.domain.SecurityEvent;
import ca.yorku.triagedesk.domain.Severity;
import ca.yorku.triagedesk.ingest.WazuhAlertParser;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;

/**
 * Turns Wazuh alerts at or above a rule level into findings. Repeated alerts of the same
 * rule for the same source IP (or host, when there is no IP) become one finding.
 */
public class WazuhAlertDetector implements Detector {

    public static final String NAME = "wazuh_alert";

    private final int minLevel;

    public WazuhAlertDetector(int minLevel) {
        this.minLevel = minLevel;
    }

    @Override
    public String name() {
        return NAME;
    }

    @Override
    public List<Finding> detect(List<SecurityEvent> events) {
        Map<String, List<SecurityEvent>> groups = new LinkedHashMap<>();
        for (SecurityEvent e : events) {
            if (WazuhAlertParser.SOURCE.equals(e.source()) && e.ruleLevel() >= minLevel) {
                String subject = e.srcIp() != null ? e.srcIp() : e.host();
                groups.computeIfAbsent(e.ruleId() + "|" + subject, k -> new ArrayList<>()).add(e);
            }
        }

        List<Finding> findings = new ArrayList<>();
        for (List<SecurityEvent> group : groups.values()) {
            SecurityEvent first = group.get(0);
            int maxLevel = group.stream().mapToInt(SecurityEvent::ruleLevel).max().orElse(minLevel);
            LinkedHashSet<String> techniques = new LinkedHashSet<>();
            group.forEach(e -> techniques.addAll(e.mitreIds()));

            String title = "Wazuh rule " + first.ruleId() + " (level " + maxLevel + "): " + first.message()
                    + (group.size() > 1 ? " [" + group.size() + " alerts]" : "");
            findings.add(new Finding(NAME, title, Severity.fromWazuhLevel(maxLevel),
                    DetectorSupport.common(group, SecurityEvent::srcIp),
                    DetectorSupport.common(group, SecurityEvent::host),
                    DetectorSupport.common(group, SecurityEvent::user),
                    new ArrayList<>(techniques), null, null, group));
        }
        return findings;
    }
}
