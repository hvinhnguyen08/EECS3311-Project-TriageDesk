package ca.yorku.triagedesk.detect;

import ca.yorku.triagedesk.domain.SecurityEvent;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;
import java.util.function.Predicate;

/** Helpers shared by the detectors: grouping by source IP and sliding-window bursts. */
final class DetectorSupport {

    private DetectorSupport() {
    }

    /** Events matching the filter and having a source IP, grouped by IP, each group oldest first. */
    static Map<String, List<SecurityEvent>> bySourceIp(List<SecurityEvent> events, Predicate<SecurityEvent> filter) {
        Map<String, List<SecurityEvent>> groups = new LinkedHashMap<>();
        for (SecurityEvent e : events) {
            if (e.srcIp() != null && filter.test(e)) {
                groups.computeIfAbsent(e.srcIp(), k -> new ArrayList<>()).add(e);
            }
        }
        groups.values().forEach(list -> list.sort(Comparator.comparing(SecurityEvent::timestamp)));
        return groups;
    }

    /**
     * Finds the bursts in a time-sorted list: every event that lies in some window of length
     * {@code window} containing at least {@code threshold} events is kept, and kept events
     * more than {@code window} apart start a new burst.
     */
    static List<List<SecurityEvent>> bursts(List<SecurityEvent> sorted, int threshold, Duration window) {
        int n = sorted.size();
        boolean[] inBurst = new boolean[n];
        int start = 0;
        for (int end = 0; end < n; end++) {
            Instant endTime = sorted.get(end).timestamp();
            while (Duration.between(sorted.get(start).timestamp(), endTime).compareTo(window) > 0) {
                start++;
            }
            if (end - start + 1 >= threshold) {
                for (int k = start; k <= end; k++) {
                    inBurst[k] = true;
                }
            }
        }

        List<List<SecurityEvent>> result = new ArrayList<>();
        List<SecurityEvent> current = null;
        Instant last = null;
        for (int k = 0; k < n; k++) {
            if (!inBurst[k]) {
                continue;
            }
            SecurityEvent e = sorted.get(k);
            if (current == null || Duration.between(last, e.timestamp()).compareTo(window) > 0) {
                current = new ArrayList<>();
                result.add(current);
            }
            current.add(e);
            last = e.timestamp();
        }
        return result;
    }

    /** The value shared by all events, or null if they differ or none has one. */
    static String common(List<SecurityEvent> events, Function<SecurityEvent, String> field) {
        String value = null;
        for (SecurityEvent e : events) {
            String v = field.apply(e);
            if (v == null) {
                continue;
            }
            if (value != null && !value.equals(v)) {
                return null;
            }
            value = v;
        }
        return value;
    }

    static long distinct(List<SecurityEvent> events, Function<SecurityEvent, String> field) {
        return events.stream().map(field).filter(Objects::nonNull).distinct().count();
    }

    /** Formats a duration as "2m31s" or "45s". */
    static String format(Duration d) {
        long seconds = d.getSeconds();
        if (seconds < 60) {
            return seconds + "s";
        }
        return (seconds / 60) + "m" + (seconds % 60) + "s";
    }

    static Duration span(List<SecurityEvent> sorted) {
        return Duration.between(sorted.get(0).timestamp(), sorted.get(sorted.size() - 1).timestamp());
    }
}
