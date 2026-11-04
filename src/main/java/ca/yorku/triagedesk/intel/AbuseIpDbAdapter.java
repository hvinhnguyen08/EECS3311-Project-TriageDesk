package ca.yorku.triagedesk.intel;

import ca.yorku.triagedesk.domain.Ioc;
import ca.yorku.triagedesk.util.Json;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.nio.charset.StandardCharsets;

/**
 * Adapter for the AbuseIPDB v2 "check" API (IP addresses only). Its abuseConfidenceScore
 * is already 0-100, so it is used as the score.
 */
public class AbuseIpDbAdapter extends RestIntelAdapter {

    public static final String DEFAULT_BASE_URL = "https://api.abuseipdb.com/api/v2";

    public AbuseIpDbAdapter(String apiKey) {
        this(DEFAULT_BASE_URL, apiKey, defaultClient());
    }

    AbuseIpDbAdapter(String baseUrl, String apiKey, HttpClient http) {
        super(baseUrl, apiKey, http);
    }

    @Override
    public String name() {
        return "AbuseIPDB";
    }

    @Override
    public boolean supports(String type) {
        return Ioc.IP.equals(type);
    }

    @Override
    protected HttpRequest buildRequest(String type, String value) {
        String url = baseUrl + "/check?maxAgeInDays=90&ipAddress=" + URLEncoder.encode(value, StandardCharsets.UTF_8);
        return get(url).header("Key", apiKey).build();
    }

    @Override
    protected IntelResult parseScore(String json) {
        JsonNode data;
        try {
            data = Json.mapper().readTree(json).path("data");
        } catch (JsonProcessingException e) {
            throw new IllegalArgumentException("not JSON", e);
        }
        if (!data.has("abuseConfidenceScore")) {
            throw new IllegalArgumentException("no abuseConfidenceScore");
        }
        int score = Math.max(0, Math.min(100, data.path("abuseConfidenceScore").asInt()));
        StringBuilder summary = new StringBuilder("confidence " + score + "%, " + data.path("totalReports").asInt(0) + " reports");
        String usage = data.path("usageType").asText("");
        if (!usage.isEmpty()) {
            summary.append(", ").append(usage);
        }
        String country = data.path("countryCode").asText("");
        if (!country.isEmpty() && !country.equals("null")) {
            summary.append(", ").append(country);
        }
        return new IntelResult(score, summary.toString());
    }
}
