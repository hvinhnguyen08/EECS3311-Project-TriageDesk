package ca.yorku.triagedesk.intel;

import ca.yorku.triagedesk.config.AppConfig;
import ca.yorku.triagedesk.domain.Case;
import ca.yorku.triagedesk.domain.Ioc;
import ca.yorku.triagedesk.util.Json;
import com.fasterxml.jackson.core.type.TypeReference;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * IOC extraction and threat-intel enrichment (F07). Each indicator is looked up with every
 * provider that supports its type; the highest score wins and every provider's answer is
 * kept in the source text. Results are cached for 24 hours (in {@code <dataDir>/intel-cache.json})
 * because the free API tiers are heavily rate-limited. Private addresses are never sent out,
 * and a provider failure only marks that provider's part as unavailable.
 */
public class EnrichmentService {

    static final Duration CACHE_TTL = Duration.ofHours(24);
    /** At most this many indicators are looked up per case, to respect the free-tier rate limits. */
    static final int MAX_IOCS = 20;
    static final String CACHE_FILE = "intel-cache.json";

    /** A cached lookup; public for JSON serialisation. */
    public record CachedResult(int score, String source, Instant at) {
    }

    private final List<ThreatIntelProvider> providers;
    private final Path cacheFile;
    private final Clock clock;
    private final Map<String, CachedResult> cache = new LinkedHashMap<>();

    /** @param dataDir where the cache is saved, or null for an in-memory cache only */
    public EnrichmentService(List<ThreatIntelProvider> providers, Path dataDir, Clock clock) {
        this.providers = List.copyOf(providers);
        this.cacheFile = dataDir == null ? null : dataDir.resolve(CACHE_FILE);
        this.clock = clock;
        loadCache();
    }

    /** One adapter per service that has an API key in the configuration; services without a key are skipped. */
    public static EnrichmentService fromConfig(AppConfig config, Path dataDir) {
        List<ThreatIntelProvider> providers = new ArrayList<>();
        if (config.getAbuseIpDbApiKey() != null) {
            providers.add(new AbuseIpDbAdapter(config.getAbuseIpDbApiKey()));
        }
        if (config.getVirusTotalApiKey() != null) {
            providers.add(new VirusTotalAdapter(config.getVirusTotalApiKey()));
        }
        return new EnrichmentService(providers, dataDir, Clock.systemUTC());
    }

    /** Extracts the case's indicators (at most {@value #MAX_IOCS}) and looks each one up. */
    public List<Ioc> enrich(Case c) {
        List<Ioc> found = IocExtractor.extract(c.getEvents());
        List<Ioc> result = new ArrayList<>();
        for (Ioc ioc : found.subList(0, Math.min(MAX_IOCS, found.size()))) {
            result.add(lookup(ioc));
        }
        return result;
    }

    /** Looks one indicator up with every provider that supports its type. Never throws for provider failures. */
    public synchronized Ioc lookup(Ioc ioc) {
        if (Ioc.IP.equals(ioc.type()) && IocExtractor.isPrivateIp(ioc.value())) {
            return ioc.withScore(Ioc.UNAVAILABLE, "private address: not sent to external services");
        }
        List<ThreatIntelProvider> supporting = providers.stream().filter(p -> p.supports(ioc.type())).toList();
        if (supporting.isEmpty()) {
            return ioc.withScore(Ioc.UNAVAILABLE, providers.isEmpty()
                    ? "no threat-intel provider configured (set ABUSEIPDB_API_KEY or VIRUSTOTAL_API_KEY in .env)"
                    : "no configured provider rates " + ioc.type() + " indicators");
        }

        String key = ioc.type() + ":" + ioc.value().toLowerCase(Locale.ROOT);
        CachedResult cached = cache.get(key);
        if (cached != null && cached.at().plus(CACHE_TTL).isAfter(clock.instant())) {
            return ioc.withScore(cached.score(), cached.source() + " (cached)");
        }

        int best = Ioc.UNAVAILABLE;
        List<String> parts = new ArrayList<>();
        for (ThreatIntelProvider p : supporting) {
            try {
                IntelResult r = p.lookup(ioc.type(), ioc.value());
                best = Math.max(best, r.score());
                parts.add(p.name() + ": " + r.summary());
            } catch (ThreatIntelException e) {
                parts.add(p.name() + ": unavailable (" + e.getMessage() + ")");
            }
        }
        String source = String.join("; ", parts);
        if (best != Ioc.UNAVAILABLE) {
            cache.put(key, new CachedResult(best, source, clock.instant()));
            saveCache();
        }
        return ioc.withScore(best, source);
    }

    public List<String> providerNames() {
        return providers.stream().map(ThreatIntelProvider::name).toList();
    }

    private void loadCache() {
        if (cacheFile == null || !Files.isRegularFile(cacheFile)) {
            return;
        }
        try {
            cache.putAll(Json.mapper().readValue(cacheFile.toFile(), new TypeReference<Map<String, CachedResult>>() { }));
        } catch (IOException | RuntimeException e) {
            // A corrupt cache is ignored; it only saves lookups.
        }
    }

    private void saveCache() {
        if (cacheFile == null) {
            return;
        }
        try {
            Files.createDirectories(cacheFile.getParent());
            Path tmp = cacheFile.resolveSibling(CACHE_FILE + ".tmp");
            Json.mapper().writerWithDefaultPrettyPrinter().writeValue(tmp.toFile(), cache);
            Files.move(tmp, cacheFile, StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException e) {
            // The cache stays in memory; enrichment itself still works.
        }
    }
}
