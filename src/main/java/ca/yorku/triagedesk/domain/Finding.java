package ca.yorku.triagedesk.domain;

import java.time.Instant;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;

/** Result of one detector: a suspicious pattern with the events that support it. */
public record Finding(
        String detector,
        String title,
        Severity severity,
        String srcIp,
        String host,
        String user,
        List<String> techniqueIds,
        Instant firstSeen,
        Instant lastSeen,
        List<SecurityEvent> events) {

    public Finding {
        Objects.requireNonNull(detector, "detector");
        Objects.requireNonNull(title, "title");
        Objects.requireNonNull(severity, "severity");
        techniqueIds = techniqueIds == null ? List.of() : List.copyOf(techniqueIds);
        events = events == null ? List.of() : List.copyOf(events);
        if (events.isEmpty()) {
            throw new IllegalArgumentException("A finding needs at least one evidence event");
        }
        if (firstSeen == null) {
            firstSeen = events.stream().map(SecurityEvent::timestamp).min(Comparator.naturalOrder()).orElseThrow();
        }
        if (lastSeen == null) {
            lastSeen = events.stream().map(SecurityEvent::timestamp).max(Comparator.naturalOrder()).orElseThrow();
        }
        if (lastSeen.isBefore(firstSeen)) {
            throw new IllegalArgumentException("lastSeen is before firstSeen");
        }
    }
}
