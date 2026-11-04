package ca.yorku.triagedesk.intel;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ca.yorku.triagedesk.config.AppConfig;
import ca.yorku.triagedesk.domain.Ioc;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class EnrichmentServiceTest {

    private static final Instant NOW = Instant.parse("2026-11-03T12:00:00Z");

    @TempDir
    Path dataDir;

    /** A provider that answers a fixed score (or fails) and counts its calls. */
    private static final class FakeProvider implements ThreatIntelProvider {
        final String name;
        final List<String> types;
        final Integer score;
        final List<String> calls = new ArrayList<>();

        FakeProvider(String name, Integer score, String... types) {
            this.name = name;
            this.score = score;
            this.types = List.of(types);
        }

        public String name() { return name; }
        public boolean supports(String type) { return types.contains(type); }
        public IntelResult lookup(String type, String value) {
            calls.add(value);
            if (score == null) {
                throw new ThreatIntelException("rate limit reached (HTTP 429)");
            }
            return new IntelResult(score, "score " + score);
        }
    }

    private static Clock at(Instant t) {
        return Clock.fixed(t, ZoneOffset.UTC);
    }

    @Test
    void highestScoreWinsAndEveryAnswerIsKept() {
        FakeProvider abuse = new FakeProvider("AbuseIPDB", 87, Ioc.IP);
        FakeProvider vt = new FakeProvider("VirusTotal", 10, Ioc.IP, Ioc.HASH);
        EnrichmentService s = new EnrichmentService(List.of(abuse, vt), null, at(NOW));

        Ioc ip = s.lookup(Ioc.unscored(Ioc.IP, "203.0.113.7"));
        Ioc hash = s.lookup(Ioc.unscored(Ioc.HASH, "d41d8cd98f00b204e9800998ecf8427e"));

        assertEquals(87, ip.score());
        assertEquals("AbuseIPDB: score 87; VirusTotal: score 10", ip.source());
        assertEquals(10, hash.score());
        assertEquals(List.of("203.0.113.7"), abuse.calls, "AbuseIPDB is not asked about hashes");
    }

    @Test
    void privateAddressesAreNeverSentOut() {
        FakeProvider abuse = new FakeProvider("AbuseIPDB", 50, Ioc.IP);
        EnrichmentService s = new EnrichmentService(List.of(abuse), null, at(NOW));

        Ioc ip = s.lookup(Ioc.unscored(Ioc.IP, "192.168.1.20"));

        assertFalse(ip.isScored());
        assertEquals("private address: not sent to external services", ip.source());
        assertEquals(List.of(), abuse.calls);
    }

    @Test
    void oneFailingProviderDoesNotStopTheOther() {
        EnrichmentService s = new EnrichmentService(List.of(
                new FakeProvider("AbuseIPDB", null, Ioc.IP), new FakeProvider("VirusTotal", 3, Ioc.IP)), null, at(NOW));

        Ioc ip = s.lookup(Ioc.unscored(Ioc.IP, "203.0.113.7"));

        assertEquals(3, ip.score());
        assertEquals("AbuseIPDB: unavailable (rate limit reached (HTTP 429)); VirusTotal: score 3", ip.source());
    }

    @Test
    void allProvidersFailingOrMissingMeansUnavailable() {
        EnrichmentService failing = new EnrichmentService(List.of(new FakeProvider("AbuseIPDB", null, Ioc.IP)), null, at(NOW));
        assertFalse(failing.lookup(Ioc.unscored(Ioc.IP, "203.0.113.7")).isScored());

        EnrichmentService none = EnrichmentService.fromConfig(AppConfig.load(null, Map.of()), null);
        Ioc ip = none.lookup(Ioc.unscored(Ioc.IP, "203.0.113.7"));
        assertFalse(ip.isScored());
        assertTrue(ip.source().startsWith("no threat-intel provider configured"));
        assertEquals(List.of(), none.providerNames());

        EnrichmentService ipOnly = new EnrichmentService(List.of(new FakeProvider("AbuseIPDB", 1, Ioc.IP)), null, at(NOW));
        assertEquals("no configured provider rates domain indicators",
                ipOnly.lookup(Ioc.unscored(Ioc.DOMAIN, "sqlmap.org")).source());
    }

    @Test
    void resultsAreCachedForADayAcrossRestarts() {
        FakeProvider abuse = new FakeProvider("AbuseIPDB", 87, Ioc.IP);
        new EnrichmentService(List.of(abuse), dataDir, at(NOW)).lookup(Ioc.unscored(Ioc.IP, "203.0.113.7"));

        FakeProvider later = new FakeProvider("AbuseIPDB", 5, Ioc.IP);
        Ioc cached = new EnrichmentService(List.of(later), dataDir, at(NOW.plus(Duration.ofHours(23))))
                .lookup(Ioc.unscored(Ioc.IP, "203.0.113.7"));
        assertEquals(87, cached.score());
        assertTrue(cached.source().endsWith("(cached)"));
        assertEquals(List.of(), later.calls);

        Ioc refreshed = new EnrichmentService(List.of(later), dataDir, at(NOW.plus(Duration.ofHours(25))))
                .lookup(Ioc.unscored(Ioc.IP, "203.0.113.7"));
        assertEquals(5, refreshed.score());
        assertEquals(1, later.calls.size());
    }

    @Test
    void failuresAreNotCached() {
        EnrichmentService s = new EnrichmentService(List.of(new FakeProvider("AbuseIPDB", null, Ioc.IP)), dataDir, at(NOW));
        s.lookup(Ioc.unscored(Ioc.IP, "203.0.113.7"));

        FakeProvider ok = new FakeProvider("AbuseIPDB", 40, Ioc.IP);
        assertEquals(40, new EnrichmentService(List.of(ok), dataDir, at(NOW)).lookup(Ioc.unscored(Ioc.IP, "203.0.113.7")).score());
    }
}
