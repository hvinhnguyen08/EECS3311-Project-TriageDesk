package ca.yorku.triagedesk.ingest;

import static org.junit.jupiter.api.Assertions.assertEquals;

import ca.yorku.triagedesk.domain.SecurityEvent;
import java.io.IOException;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;

class WazuhAlertParserTest {

    private final WazuhAlertParser parser = new WazuhAlertParser();

    @Test
    void parsesAnAlertLine() throws IOException {
        List<SecurityEvent> events = parser.parse(LogParserFactory.readLines(Path.of("samples/alerts.json")), "alerts.json");
        SecurityEvent e = events.get(1);

        assertEquals("alerts.json:2", e.id());
        assertEquals(Instant.parse("2026-10-28T09:14:30.512Z"), e.timestamp());
        assertEquals(WazuhAlertParser.SOURCE, e.source());
        assertEquals("web01", e.host());
        assertEquals("admin", e.user());
        assertEquals("203.0.113.7", e.srcIp());
        assertEquals("5710", e.ruleId());
        assertEquals(5, e.ruleLevel());
        assertEquals(List.of("T1110.001", "T1021.004"), e.mitreIds());
        assertEquals(SecurityEvent.AUTH_FAILURE, e.category());
        assertEquals("1761642870.2001", e.attribute("alertId"));
        assertEquals("/var/log/auth.log", e.attribute("location"));
        assertEquals("sshd: Attempt to login using a non-existent user", e.message());
    }

    @Test
    void categorisesTheSampleFile() throws IOException {
        List<SecurityEvent> events = parser.parse(LogParserFactory.readLines(Path.of("samples/alerts.json")), "alerts.json");

        Map<String, Long> byCategory = events.stream()
                .collect(Collectors.groupingBy(SecurityEvent::category, Collectors.counting()));
        assertEquals(12, events.size());
        assertEquals(4L, byCategory.get(SecurityEvent.AUTH_FAILURE));
        assertEquals(2L, byCategory.get(SecurityEvent.AUTH_SUCCESS));
        assertEquals(1L, byCategory.get(SecurityEvent.PRIVILEGE));
        assertEquals(5L, byCategory.get(SecurityEvent.ALERT));
    }

    @Test
    void malformedAlertsAreSkipped() throws IOException {
        List<SecurityEvent> events = parser.parse(
                LogParserFactory.readLines(Path.of("samples/errors/alerts-with-bad-lines.json")), "bad.json");

        assertEquals(List.of("bad.json:1", "bad.json:5"), events.stream().map(SecurityEvent::id).toList());
    }

    @Test
    void acceptsTheTimestampOffsetStyles() {
        Instant expected = Instant.parse("2026-10-28T09:14:30.512Z");

        assertEquals(expected, WazuhAlertParser.parseTimestamp("2026-10-28T09:14:30.512+0000"));
        assertEquals(expected, WazuhAlertParser.parseTimestamp("2026-10-28T09:14:30.512+00:00"));
        assertEquals(expected, WazuhAlertParser.parseTimestamp("2026-10-28T09:14:30.512Z"));
        assertEquals(expected, WazuhAlertParser.parseTimestamp("2026-10-28T05:14:30.512-0400"));
    }
}
