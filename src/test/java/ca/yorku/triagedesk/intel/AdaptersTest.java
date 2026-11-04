package ca.yorku.triagedesk.intel;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ca.yorku.triagedesk.domain.Ioc;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** Both adapters against a local fake server: request format, score conversion and error mapping. */
class AdaptersTest {

    private HttpServer server;
    private final AtomicReference<String> lastUri = new AtomicReference<>();
    private final AtomicReference<String> lastKeyHeader = new AtomicReference<>();
    private volatile int status = 200;
    private volatile String response = "{}";

    @BeforeEach
    void start() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", ex -> {
            lastUri.set(ex.getRequestURI().toString());
            String key = ex.getRequestHeaders().getFirst("Key");
            lastKeyHeader.set(key != null ? "Key=" + key : "x-apikey=" + ex.getRequestHeaders().getFirst("x-apikey"));
            byte[] b = response.getBytes(StandardCharsets.UTF_8);
            ex.sendResponseHeaders(status, b.length == 0 ? -1 : b.length);
            try (OutputStream os = ex.getResponseBody()) {
                os.write(b);
            }
        });
        server.start();
    }

    @AfterEach
    void stop() {
        server.stop(0);
    }

    private String base() {
        return "http://127.0.0.1:" + server.getAddress().getPort() + "/api";
    }

    private AbuseIpDbAdapter abuse() {
        return new AbuseIpDbAdapter(base(), "abuse-key", HttpClient.newHttpClient());
    }

    private VirusTotalAdapter vt() {
        return new VirusTotalAdapter(base(), "vt-key", HttpClient.newHttpClient());
    }

    @Test
    void abuseIpDbRequestAndScore() {
        response = "{\"data\":{\"ipAddress\":\"203.0.113.7\",\"abuseConfidenceScore\":87,\"totalReports\":120,"
                + "\"usageType\":\"Data Center/Web Hosting/Transit\",\"countryCode\":\"NL\"}}";

        IntelResult r = abuse().lookup(Ioc.IP, "203.0.113.7");

        assertEquals("/api/check?maxAgeInDays=90&ipAddress=203.0.113.7", lastUri.get());
        assertEquals("Key=abuse-key", lastKeyHeader.get());
        assertEquals(87, r.score());
        assertEquals("confidence 87%, 120 reports, Data Center/Web Hosting/Transit, NL", r.summary());
        assertTrue(abuse().supports(Ioc.IP));
        assertFalse(abuse().supports(Ioc.HASH));
        assertThrows(ThreatIntelException.class, () -> abuse().lookup(Ioc.HASH, "abc"));
    }

    @Test
    void virusTotalRequestsPerTypeAndScore() {
        response = "{\"data\":{\"attributes\":{\"last_analysis_stats\":"
                + "{\"malicious\":8,\"suspicious\":2,\"harmless\":60,\"undetected\":20,\"timeout\":0}}}}";

        IntelResult ip = vt().lookup(Ioc.IP, "203.0.113.7");
        assertEquals("/api/ip_addresses/203.0.113.7", lastUri.get());
        assertEquals("x-apikey=vt-key", lastKeyHeader.get());
        assertEquals(10, ip.score(), "(8 + 2/2) of 90 engines");
        assertEquals("8/90 engines flag it as malicious, 2 as suspicious", ip.summary());

        vt().lookup(Ioc.DOMAIN, "sqlmap.org");
        assertEquals("/api/domains/sqlmap.org", lastUri.get());
        vt().lookup(Ioc.HASH, "d41d8cd98f00b204e9800998ecf8427e");
        assertEquals("/api/files/d41d8cd98f00b204e9800998ecf8427e", lastUri.get());
        vt().lookup(Ioc.URL, "https://sqlmap.org");
        assertEquals("/api/urls/aHR0cHM6Ly9zcWxtYXAub3Jn", lastUri.get(), "unpadded base64url of the URL");
    }

    @Test
    void virusTotalUnknownIndicatorScoresZero() {
        status = 404;
        response = "{\"error\":{\"code\":\"NotFoundError\"}}";

        IntelResult r = vt().lookup(Ioc.HASH, "d41d8cd98f00b204e9800998ecf8427e");

        assertEquals(0, r.score());
        assertEquals("not known to VirusTotal", r.summary());
    }

    @Test
    void errorsAreMappedAndNeverShowTheKey() {
        status = 401;
        ThreatIntelException auth = assertThrows(ThreatIntelException.class, () -> abuse().lookup(Ioc.IP, "203.0.113.7"));
        assertEquals("API key rejected (HTTP 401)", auth.getMessage());

        status = 429;
        assertEquals("rate limit reached (HTTP 429)",
                assertThrows(ThreatIntelException.class, () -> vt().lookup(Ioc.IP, "203.0.113.7")).getMessage());

        status = 404;
        assertThrows(ThreatIntelException.class, () -> abuse().lookup(Ioc.IP, "203.0.113.7"));

        status = 200;
        response = "{\"data\":{}}";
        assertEquals("unexpected response",
                assertThrows(ThreatIntelException.class, () -> abuse().lookup(Ioc.IP, "203.0.113.7")).getMessage());

        AbuseIpDbAdapter adapter = abuse();
        server.stop(0);
        ThreatIntelException down = assertThrows(ThreatIntelException.class, () -> adapter.lookup(Ioc.IP, "203.0.113.7"));
        assertTrue(down.getMessage().startsWith("could not reach the service"));
        assertFalse(down.getMessage().contains("abuse-key"));
    }
}
