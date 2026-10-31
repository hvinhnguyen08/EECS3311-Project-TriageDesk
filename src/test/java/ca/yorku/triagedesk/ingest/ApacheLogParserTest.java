package ca.yorku.triagedesk.ingest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ca.yorku.triagedesk.domain.SecurityEvent;
import java.io.IOException;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;

class ApacheLogParserTest {

    private final ApacheLogParser parser = new ApacheLogParser();

    @Test
    void combinedLogFormat() {
        List<SecurityEvent> events = parser.parse(List.of(
                "192.168.1.20 - alice [28/Oct/2026:10:20:11 +0000] \"POST /admin/login.php?next=%2Fadmin HTTP/1.1\" 302 0 "
                        + "\"https://shop.example.com/admin/\" \"Mozilla/5.0 (Windows NT 10.0) Firefox/131.0\""), "access.log");

        SecurityEvent e = events.get(0);
        assertEquals(Instant.parse("2026-10-28T10:20:11Z"), e.timestamp());
        assertEquals(SecurityEvent.WEB_REQUEST, e.category());
        assertEquals("192.168.1.20", e.srcIp());
        assertEquals("alice", e.user());
        assertEquals("POST", e.attribute("method"));
        assertEquals("/admin/login.php?next=%2Fadmin", e.attribute("path"));
        assertEquals("HTTP/1.1", e.attribute("protocol"));
        assertEquals("302", e.attribute("status"));
        assertEquals("0", e.attribute("bytes"));
        assertEquals("https://shop.example.com/admin/", e.attribute("referrer"));
        assertEquals("Mozilla/5.0 (Windows NT 10.0) Firefox/131.0", e.attribute("userAgent"));
    }

    @Test
    void commonLogFormatWithTimeZoneOffset() {
        SecurityEvent e = parser.parse(List.of(
                "127.0.0.1 - frank [10/Oct/2026:13:55:36 -0700] \"GET /apache_pb.gif HTTP/1.0\" 200 2326"), "a").get(0);

        assertEquals(Instant.parse("2026-10-10T20:55:36Z"), e.timestamp());
        assertEquals("frank", e.user());
        assertNull(e.attribute("userAgent"));
    }

    @Test
    void emptyRequestAndDashesBecomeNull() {
        SecurityEvent e = parser.parse(List.of(
                "192.168.1.20 - - [28/Oct/2026:10:50:00 +0000] \"-\" 408 0 \"-\" \"-\""), "a").get(0);

        assertNull(e.user());
        assertNull(e.attribute("method"));
        assertNull(e.attribute("path"));
        assertNull(e.attribute("referrer"));
        assertEquals("408", e.attribute("status"));
    }

    @Test
    void escapedQuotesInsideTheRequest() {
        SecurityEvent e = parser.parse(List.of(
                "198.51.100.23 - - [28/Oct/2026:10:31:40 +0000] \"GET /search?q=\\\"x\\\" HTTP/1.1\" 200 10 \"-\" \"curl/8.0\""), "a").get(0);

        assertEquals("/search?q=\\\"x\\\"", e.attribute("path"));
        assertEquals("curl/8.0", e.attribute("userAgent"));
    }

    @Test
    void malformedLinesAreSkipped() {
        List<SecurityEvent> events = parser.parse(List.of(
                "garbage",
                "192.168.1.20 - - [99/Foo/2026:10:50:00 +0000] \"GET / HTTP/1.1\" 200 1",
                "192.168.1.20 - - [28/Oct/2026:10:50:00 +0000] \"GET / HTTP/1.1\" 200 1"), "a");

        assertEquals(1, events.size());
        assertEquals("a:3", events.get(0).id());
    }

    @Test
    void parsesTheSampleFile() throws IOException {
        List<SecurityEvent> events = parser.parse(LogParserFactory.readLines(Path.of("samples/access.log")), "access.log");

        assertEquals(51, events.size());
        long scan404s = events.stream()
                .filter(e -> "198.51.100.23".equals(e.srcIp()) && "404".equals(e.attribute("status")))
                .count();
        assertEquals(37, scan404s);
        assertTrue(events.stream().allMatch(e -> e.source().equals(ApacheLogParser.SOURCE)));
    }
}
