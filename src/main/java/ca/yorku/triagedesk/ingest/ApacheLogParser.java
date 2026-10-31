package ca.yorku.triagedesk.ingest;

import ca.yorku.triagedesk.domain.SecurityEvent;
import java.time.DateTimeException;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Parses Apache/Nginx access logs in the common or combined log format. */
public class ApacheLogParser implements LogParser {

    public static final String SOURCE = "apache";

    private static final String QUOTED = "\"((?:[^\"\\\\]|\\\\.)*)\"";
    private static final Pattern LINE = Pattern.compile(
            "^(\\S+) (\\S+) (\\S+) \\[([^\\]]+)\\] " + QUOTED + " (\\d{3}) (\\S+)(?: " + QUOTED + " " + QUOTED + ")?.*$");
    private static final DateTimeFormatter TIME =
            DateTimeFormatter.ofPattern("dd/MMM/yyyy:HH:mm:ss Z", Locale.ENGLISH);

    /** True if the line looks like an access-log entry (used for format detection). */
    public static boolean matchesLine(String line) {
        return LINE.matcher(line).matches();
    }

    @Override
    public List<SecurityEvent> parse(List<String> lines, String batchId) {
        List<SecurityEvent> events = new ArrayList<>();
        for (int i = 0; i < lines.size(); i++) {
            String line = lines.get(i).strip();
            if (line.isEmpty()) {
                continue;
            }
            Matcher m = LINE.matcher(line);
            if (!m.matches()) {
                continue;
            }
            try {
                events.add(toEvent(m, batchId, i + 1));
            } catch (DateTimeException e) {
                // Bad timestamp: skipped.
            }
        }
        return events;
    }

    private SecurityEvent toEvent(Matcher m, String batchId, int lineNumber) {
        Instant timestamp = OffsetDateTime.parse(m.group(4), TIME).toInstant();
        String request = m.group(5);
        String status = m.group(6);

        String method = null;
        String path = null;
        String protocol = null;
        String[] parts = request.split(" ");
        if (parts.length >= 2) {
            method = parts[0];
            path = parts[1];
            protocol = parts.length >= 3 ? parts[2] : null;
        } else if (!request.equals("-") && !request.isEmpty()) {
            path = request;
        }

        return SecurityEvent.builder(LogParser.eventId(batchId, lineNumber), batchId, timestamp)
                .source(SOURCE)
                .srcIp(m.group(1))
                .user(dash(m.group(3)))
                .message(request + " " + status)
                .category(SecurityEvent.WEB_REQUEST)
                .attribute("method", method)
                .attribute("path", path)
                .attribute("protocol", protocol)
                .attribute("status", status)
                .attribute("bytes", dash(m.group(7)))
                .attribute("referrer", dash(m.group(8)))
                .attribute("userAgent", dash(m.group(9)))
                .build();
    }

    private static String dash(String value) {
        return value == null || value.equals("-") || value.isEmpty() ? null : value;
    }
}
