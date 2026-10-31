package ca.yorku.triagedesk.ingest;

import ca.yorku.triagedesk.domain.SecurityEvent;
import java.time.Clock;
import java.time.DateTimeException;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parses Linux auth.log (sshd, sudo and other syslog lines). Both the classic syslog
 * prefix ("Oct 28 09:14:02 host prog[pid]: msg") and the ISO prefix used by newer
 * rsyslog configurations are supported.
 */
public class AuthLogParser implements LogParser {

    public static final String SOURCE = "auth";

    private static final Pattern CLASSIC = Pattern.compile(
            "^([A-Z][a-z]{2})\\s+(\\d{1,2}) (\\d{2}:\\d{2}:\\d{2}) (\\S+) ([^\\s\\[:]+)(?:\\[(\\d+)\\])?: (.*)$");
    private static final Pattern ISO = Pattern.compile(
            "^(\\d{4}-\\d{2}-\\d{2}T\\S+) (\\S+) ([^\\s\\[:]+)(?:\\[(\\d+)\\])?: (.*)$");

    private static final Pattern FAILED = Pattern.compile(
            "Failed (\\S+) for (?:invalid user )?(\\S+) from (\\S+) port (\\d+)");
    private static final Pattern ACCEPTED = Pattern.compile(
            "Accepted (\\S+) for (\\S+) from (\\S+) port (\\d+)");
    private static final Pattern INVALID_USER = Pattern.compile("Invalid user (\\S*) from (\\S+)");
    private static final Pattern SUDO = Pattern.compile("^\\s*(\\S+) : .*?COMMAND=(.*)$");

    private static final List<String> MONTHS = List.of(
            "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec");

    private final Clock clock;
    private final ZoneId zone;

    /** Classic syslog lines have no year or zone: the current year is assumed and times are read in UTC. */
    public AuthLogParser() {
        this(Clock.systemUTC(), ZoneOffset.UTC);
    }

    public AuthLogParser(Clock clock, ZoneId zone) {
        this.clock = clock;
        this.zone = zone;
    }

    /** True if the line has a syslog prefix this parser understands (used for format detection). */
    public static boolean matchesLine(String line) {
        return CLASSIC.matcher(line).matches() || ISO.matcher(line).matches();
    }

    @Override
    public List<SecurityEvent> parse(List<String> lines, String batchId) {
        List<SecurityEvent> events = new ArrayList<>();
        for (int i = 0; i < lines.size(); i++) {
            String line = lines.get(i).strip();
            if (line.isEmpty()) {
                continue;
            }
            try {
                SecurityEvent e = parseLine(line, batchId, i + 1);
                if (e != null) {
                    events.add(e);
                }
            } catch (DateTimeException e) {
                // Impossible date (for example Feb 30): skipped.
            }
        }
        return events;
    }

    private SecurityEvent parseLine(String line, String batchId, int lineNumber) {
        Instant timestamp;
        String host;
        String program;
        String pid;
        String message;

        Matcher m = CLASSIC.matcher(line);
        if (m.matches()) {
            timestamp = classicTimestamp(m.group(1), Integer.parseInt(m.group(2)), m.group(3));
            host = m.group(4);
            program = m.group(5);
            pid = m.group(6);
            message = m.group(7);
        } else {
            m = ISO.matcher(line);
            if (!m.matches()) {
                return null;
            }
            timestamp = isoTimestamp(m.group(1));
            host = m.group(2);
            program = m.group(3);
            pid = m.group(4);
            message = m.group(5);
        }

        SecurityEvent.Builder b = SecurityEvent.builder(LogParser.eventId(batchId, lineNumber), batchId, timestamp)
                .source(SOURCE)
                .host(host)
                .message(message)
                .category(SecurityEvent.OTHER)
                .attribute("program", program)
                .attribute("pid", pid);

        Matcher f;
        if ((f = FAILED.matcher(message)).find()) {
            b.category(SecurityEvent.AUTH_FAILURE).user(f.group(2)).srcIp(f.group(3))
                    .attribute("authMethod", f.group(1)).attribute("port", f.group(4));
        } else if ((f = ACCEPTED.matcher(message)).find()) {
            b.category(SecurityEvent.AUTH_SUCCESS).user(f.group(2)).srcIp(f.group(3))
                    .attribute("authMethod", f.group(1)).attribute("port", f.group(4));
        } else if ((f = INVALID_USER.matcher(message)).find()) {
            // Always followed by a "Failed ... for invalid user" line, so it is not counted as a failure twice.
            b.user(f.group(1).isEmpty() ? null : f.group(1)).srcIp(f.group(2)).attribute("invalidUser", "true");
        } else if (program.equals("sudo") && (f = SUDO.matcher(message)).find()) {
            b.category(SecurityEvent.PRIVILEGE).user(f.group(1)).attribute("command", f.group(2).strip());
            if (message.contains("NOT in sudoers") || message.contains("authentication failure")) {
                b.attribute("denied", "true");
            }
        }
        return b.build();
    }

    private Instant classicTimestamp(String month, int day, String time) {
        int monthNumber = MONTHS.indexOf(month) + 1;
        if (monthNumber == 0) {
            throw new DateTimeException("Unknown month " + month);
        }
        Instant now = clock.instant();
        int year = now.atZone(zone).getYear();
        LocalDateTime local = LocalDateTime.of(year, monthNumber, day, 0, 0).with(LocalTime.parse(time));
        Instant result = local.atZone(zone).toInstant();
        // A December log read in January belongs to the previous year.
        if (result.isAfter(now.plus(Duration.ofDays(1)))) {
            result = local.minusYears(1).atZone(zone).toInstant();
        }
        return result;
    }

    private Instant isoTimestamp(String value) {
        try {
            return OffsetDateTime.parse(value).toInstant();
        } catch (DateTimeParseException e) {
            return LocalDateTime.parse(value).atZone(zone).toInstant();
        }
    }
}
