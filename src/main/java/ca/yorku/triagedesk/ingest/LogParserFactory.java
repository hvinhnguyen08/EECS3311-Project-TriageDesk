package ca.yorku.triagedesk.ingest;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/**
 * Creator of the Factory Method pattern (parameterized variant): detectFormat() inspects
 * the first lines of a file and createParser() returns the matching LogParser, so the
 * import workflow depends only on the LogParser interface.
 */
public class LogParserFactory {

    public static final String WAZUH = "wazuh";
    public static final String AUTH = "auth";
    public static final String APACHE = "apache";

    /** How many non-blank lines are inspected before giving up. */
    private static final int SAMPLE_LINES = 20;

    public String detectFormat(Path path) throws IOException {
        return detectFormat(readLines(path));
    }

    public String detectFormat(List<String> lines) {
        int inspected = 0;
        for (String raw : lines) {
            String line = raw.strip();
            if (line.isEmpty()) {
                continue;
            }
            if (line.startsWith("{")) {
                return WAZUH;
            }
            if (AuthLogParser.matchesLine(line)) {
                return AUTH;
            }
            if (ApacheLogParser.matchesLine(line)) {
                return APACHE;
            }
            if (++inspected >= SAMPLE_LINES) {
                break;
            }
        }
        throw new UnsupportedFormatException("Unsupported file format");
    }

    public LogParser createParser(String format) {
        if (format == null) {
            throw new UnsupportedFormatException("Unsupported file format");
        }
        return switch (format) {
            case WAZUH -> new WazuhAlertParser();
            case AUTH -> new AuthLogParser();
            case APACHE -> new ApacheLogParser();
            default -> throw new UnsupportedFormatException("Unsupported file format: " + format);
        };
    }

    /**
     * Reads a log file as UTF-8. Invalid byte sequences (common in logs) are replaced rather
     * than failing the import, and a leading byte-order mark is removed.
     */
    public static List<String> readLines(Path path) throws IOException {
        String content = new String(Files.readAllBytes(path), StandardCharsets.UTF_8);
        if (content.startsWith("﻿")) {
            content = content.substring(1);
        }
        return content.lines().toList();
    }
}
