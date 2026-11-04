package ca.yorku.triagedesk.intel;

import ca.yorku.triagedesk.domain.Ioc;
import ca.yorku.triagedesk.util.Json;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Adapter for the VirusTotal v3 API (IPs, domains, URLs and file hashes). VirusTotal reports
 * how many antivirus engines flag an indicator; the score is the share of engines that call
 * it malicious (suspicious counts half), scaled to 0-100. An indicator VirusTotal has never
 * seen (HTTP 404) scores 0.
 */
public class VirusTotalAdapter extends RestIntelAdapter {

    public static final String DEFAULT_BASE_URL = "https://www.virustotal.com/api/v3";

    public VirusTotalAdapter(String apiKey) {
        this(DEFAULT_BASE_URL, apiKey, defaultClient());
    }

    VirusTotalAdapter(String baseUrl, String apiKey, HttpClient http) {
        super(baseUrl, apiKey, http);
    }

    @Override
    public String name() {
        return "VirusTotal";
    }

    @Override
    public boolean supports(String type) {
        return Ioc.IP.equals(type) || Ioc.DOMAIN.equals(type) || Ioc.URL.equals(type) || Ioc.HASH.equals(type);
    }

    @Override
    protected HttpRequest buildRequest(String type, String value) {
        String path = switch (type) {
            case Ioc.IP -> "/ip_addresses/" + encode(value);
            case Ioc.DOMAIN -> "/domains/" + encode(value);
            case Ioc.HASH -> "/files/" + encode(value);
            // URL identifiers are the URL in unpadded base64url
            case Ioc.URL -> "/urls/" + Base64.getUrlEncoder().withoutPadding().encodeToString(value.getBytes(StandardCharsets.UTF_8));
            default -> throw new ThreatIntelException("unsupported type " + type);
        };
        return get(baseUrl + path).header("x-apikey", apiKey).build();
    }

    @Override
    protected IntelResult parseScore(String json) {
        JsonNode stats;
        try {
            stats = Json.mapper().readTree(json).path("data").path("attributes").path("last_analysis_stats");
        } catch (JsonProcessingException e) {
            throw new IllegalArgumentException("not JSON", e);
        }
        if (!stats.isObject()) {
            throw new IllegalArgumentException("no last_analysis_stats");
        }
        int malicious = stats.path("malicious").asInt(0);
        int suspicious = stats.path("suspicious").asInt(0);
        int total = 0;
        for (JsonNode n : stats) {
            total += n.asInt(0);
        }
        int score = total == 0 ? 0 : (int) Math.round(100.0 * (malicious + 0.5 * suspicious) / total);
        String summary = malicious + "/" + total + " engines flag it as malicious"
                + (suspicious > 0 ? ", " + suspicious + " as suspicious" : "");
        return new IntelResult(Math.min(100, score), summary);
    }

    @Override
    protected IntelResult notFound(String type, String value) {
        return new IntelResult(0, "not known to VirusTotal");
    }

    private static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
