package ca.yorku.triagedesk.testutil;

import ca.yorku.triagedesk.domain.SecurityEvent;
import ca.yorku.triagedesk.ingest.ApacheLogParser;
import ca.yorku.triagedesk.ingest.AuthLogParser;
import ca.yorku.triagedesk.ingest.LogParserFactory;
import ca.yorku.triagedesk.ingest.WazuhAlertParser;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;

/** The files in samples/, parsed deterministically (auth.log times are read as UTC in 2026). */
public final class SampleData {

    private SampleData() {
    }

    public static List<SecurityEvent> authLog() {
        AuthLogParser parser = new AuthLogParser(
                Clock.fixed(Instant.parse("2026-11-01T00:00:00Z"), ZoneOffset.UTC), ZoneOffset.UTC);
        return parser.parse(lines("samples/auth.log"), "auth.log");
    }

    public static List<SecurityEvent> accessLog() {
        return new ApacheLogParser().parse(lines("samples/access.log"), "access.log");
    }

    public static List<SecurityEvent> alerts() {
        return new WazuhAlertParser().parse(lines("samples/alerts.json"), "alerts.json");
    }

    public static List<SecurityEvent> all() {
        List<SecurityEvent> events = new ArrayList<>(alerts());
        events.addAll(authLog());
        events.addAll(accessLog());
        return events;
    }

    private static List<String> lines(String path) {
        try {
            return LogParserFactory.readLines(Path.of(path));
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
