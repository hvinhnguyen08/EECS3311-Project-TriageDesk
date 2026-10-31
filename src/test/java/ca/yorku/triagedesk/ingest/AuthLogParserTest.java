package ca.yorku.triagedesk.ingest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import ca.yorku.triagedesk.domain.SecurityEvent;
import java.io.IOException;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;

class AuthLogParserTest {

    private final AuthLogParser parser = new AuthLogParser(
            Clock.fixed(Instant.parse("2026-11-01T00:00:00Z"), ZoneOffset.UTC), ZoneOffset.UTC);

    private SecurityEvent parseOne(String line) {
        List<SecurityEvent> events = parser.parse(List.of(line), "auth.log");
        assertEquals(1, events.size(), "expected one event for: " + line);
        return events.get(0);
    }

    @Test
    void failedPasswordForInvalidUser() {
        SecurityEvent e = parseOne(
                "Oct 28 09:14:31 web01 sshd[2219]: Failed password for invalid user admin from 203.0.113.7 port 52178 ssh2");

        assertEquals("auth.log:1", e.id());
        assertEquals(Instant.parse("2026-10-28T09:14:31Z"), e.timestamp());
        assertEquals(SecurityEvent.AUTH_FAILURE, e.category());
        assertEquals("web01", e.host());
        assertEquals("admin", e.user());
        assertEquals("203.0.113.7", e.srcIp());
        assertEquals("sshd", e.attribute("program"));
        assertEquals("2219", e.attribute("pid"));
        assertEquals("password", e.attribute("authMethod"));
        assertEquals("52178", e.attribute("port"));
    }

    @Test
    void acceptedLogin() {
        SecurityEvent e = parseOne(
                "Oct 28 09:17:05 web01 sshd[2260]: Accepted password for deploy from 203.0.113.7 port 52388 ssh2");

        assertEquals(SecurityEvent.AUTH_SUCCESS, e.category());
        assertEquals("deploy", e.user());
        assertEquals("203.0.113.7", e.srcIp());
    }

    @Test
    void invalidUserLineIsNotCountedAsAFailure() {
        SecurityEvent e = parseOne("Oct 28 09:14:30 web01 sshd[2219]: Invalid user admin from 203.0.113.7 port 52178");

        assertEquals(SecurityEvent.OTHER, e.category());
        assertEquals("admin", e.user());
        assertEquals("true", e.attribute("invalidUser"));
    }

    @Test
    void sudoCommandsAndDenials() {
        SecurityEvent allowed = parseOne(
                "Oct 28 09:05:40 web01 sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/systemctl restart nginx");
        SecurityEvent denied = parseOne(
                "Oct 28 09:17:41 web01 sudo:   deploy : user NOT in sudoers ; TTY=pts/1 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash");

        assertEquals(SecurityEvent.PRIVILEGE, allowed.category());
        assertEquals("alice", allowed.user());
        assertEquals("/usr/bin/systemctl restart nginx", allowed.attribute("command"));
        assertNull(allowed.attribute("denied"));

        assertEquals("deploy", denied.user());
        assertEquals("true", denied.attribute("denied"));
    }

    @Test
    void isoTimestampFormat() {
        SecurityEvent e = parseOne(
                "2026-10-28T09:14:02.123456+00:00 web01 sshd[2211]: Failed password for root from 203.0.113.7 port 52144 ssh2");

        assertEquals(Instant.parse("2026-10-28T09:14:02.123456Z"), e.timestamp());
        assertEquals(SecurityEvent.AUTH_FAILURE, e.category());
    }

    @Test
    void decemberLogReadInJanuaryUsesPreviousYear() {
        AuthLogParser january = new AuthLogParser(
                Clock.fixed(Instant.parse("2027-01-02T00:00:00Z"), ZoneOffset.UTC), ZoneOffset.UTC);

        List<SecurityEvent> events = january.parse(
                List.of("Dec 31 23:59:59 web01 sshd[1]: Accepted password for bob from 192.168.1.35 port 1 ssh2"), "a");

        assertEquals(Instant.parse("2026-12-31T23:59:59Z"), events.get(0).timestamp());
    }

    @Test
    void unparseableLinesAreSkippedButLineNumbersStayAccurate() {
        List<SecurityEvent> events = parser.parse(List.of(
                "not a syslog line",
                "",
                "Feb 30 10:00:00 web01 sshd[1]: impossible date",
                "Oct 28 10:02:33 web01 sshd[2390]: Failed password for bob from 192.168.1.35 port 50433 ssh2"), "auth.log");

        assertEquals(1, events.size());
        assertEquals("auth.log:4", events.get(0).id());
    }

    @Test
    void parsesTheSampleFile() throws IOException {
        List<SecurityEvent> events = parser.parse(LogParserFactory.readLines(Path.of("samples/auth.log")), "auth.log");

        Map<String, Long> byCategory = events.stream()
                .collect(Collectors.groupingBy(SecurityEvent::category, Collectors.counting()));
        assertEquals(35, events.size());
        assertEquals(17L, byCategory.get(SecurityEvent.AUTH_FAILURE));
        assertEquals(3L, byCategory.get(SecurityEvent.AUTH_SUCCESS));
        assertEquals(2L, byCategory.get(SecurityEvent.PRIVILEGE));

        Map<String, Long> failuresByIp = events.stream()
                .filter(e -> e.category().equals(SecurityEvent.AUTH_FAILURE))
                .collect(Collectors.groupingBy(SecurityEvent::srcIp, Collectors.counting()));
        assertEquals(13L, failuresByIp.get("203.0.113.7"));
        assertEquals(35, events.stream().map(SecurityEvent::id).distinct().count(), "event IDs are unique");
    }
}
