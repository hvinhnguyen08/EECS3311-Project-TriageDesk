package ca.yorku.triagedesk.detect;

import ca.yorku.triagedesk.domain.SecurityEvent;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/** Builds synthetic events for the detector tests. */
final class TestEvents {

    static final Instant T0 = Instant.parse("2026-10-28T09:00:00Z");

    private static int counter;

    private TestEvents() {
    }

    static SecurityEvent auth(String category, String ip, String user, int secondsAfterT0) {
        return SecurityEvent.builder("t:" + (++counter), "t", T0.plusSeconds(secondsAfterT0))
                .source("auth").host("web01").user(user).srcIp(ip).category(category).build();
    }

    /** {@code count} failed logins from one IP, {@code spacingSeconds} apart, starting at {@code startSeconds}. */
    static List<SecurityEvent> failures(String ip, int count, int startSeconds, int spacingSeconds) {
        List<SecurityEvent> events = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            events.add(auth(SecurityEvent.AUTH_FAILURE, ip, "root", startSeconds + i * spacingSeconds));
        }
        return events;
    }

    static SecurityEvent web(String ip, String status, int secondsAfterT0) {
        return SecurityEvent.builder("w:" + (++counter), "w", T0.plusSeconds(secondsAfterT0))
                .source("apache").srcIp(ip).category(SecurityEvent.WEB_REQUEST)
                .attribute("status", status).attribute("userAgent", "gobuster/3.6").build();
    }
}
