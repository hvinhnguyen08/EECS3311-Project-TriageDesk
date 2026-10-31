package ca.yorku.triagedesk.ingest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class LogParserFactoryTest {

    private final LogParserFactory factory = new LogParserFactory();

    @TempDir
    Path dir;

    @Test
    void detectsEachSampleFormat() throws IOException {
        assertEquals(LogParserFactory.WAZUH, factory.detectFormat(Path.of("samples/alerts.json")));
        assertEquals(LogParserFactory.AUTH, factory.detectFormat(Path.of("samples/auth.log")));
        assertEquals(LogParserFactory.APACHE, factory.detectFormat(Path.of("samples/access.log")));
    }

    @Test
    void unsupportedFileIsRejected() {
        UnsupportedFormatException e = assertThrows(UnsupportedFormatException.class,
                () -> factory.detectFormat(Path.of("samples/errors/unsupported-format.txt")));
        assertEquals("Unsupported file format", e.getMessage());
        assertThrows(UnsupportedFormatException.class, () -> factory.detectFormat(List.of()));
    }

    @Test
    void leadingBlankAndUnknownLinesAreTolerated() {
        assertEquals(LogParserFactory.AUTH, factory.detectFormat(List.of(
                "",
                "-- Logs begin at Mon 2026-10-26 --",
                "Oct 28 09:14:02 web01 sshd[2211]: Failed password for root from 203.0.113.7 port 52144 ssh2")));
    }

    @Test
    void createsTheParserForEachFormat() {
        assertInstanceOf(WazuhAlertParser.class, factory.createParser(LogParserFactory.WAZUH));
        assertInstanceOf(AuthLogParser.class, factory.createParser(LogParserFactory.AUTH));
        assertInstanceOf(ApacheLogParser.class, factory.createParser(LogParserFactory.APACHE));
        assertThrows(UnsupportedFormatException.class, () -> factory.createParser("csv"));
        assertThrows(UnsupportedFormatException.class, () -> factory.createParser(null));
    }

    @Test
    void readLinesRemovesByteOrderMarkAndReplacesBadBytes() throws IOException {
        Path file = dir.resolve("bom.log");
        byte[] text = "{\"timestamp\":\"x\"}\nsecond\n".getBytes(StandardCharsets.UTF_8);
        byte[] bytes = new byte[text.length + 4];
        bytes[0] = (byte) 0xEF;
        bytes[1] = (byte) 0xBB;
        bytes[2] = (byte) 0xBF;
        System.arraycopy(text, 0, bytes, 3, text.length);
        bytes[bytes.length - 1] = (byte) 0xFF; // invalid UTF-8 at the end
        Files.write(file, bytes);

        List<String> lines = LogParserFactory.readLines(file);

        assertEquals("{\"timestamp\":\"x\"}", lines.get(0));
        assertEquals(LogParserFactory.WAZUH, factory.detectFormat(file));
        assertEquals(3, lines.size());
    }
}
