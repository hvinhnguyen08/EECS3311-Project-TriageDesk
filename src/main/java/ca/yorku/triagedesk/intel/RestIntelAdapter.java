package ca.yorku.triagedesk.intel;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.time.Duration;
import java.util.Objects;

/**
 * Template Method for REST threat-intel adapters. {@link #lookup} fixes the steps (build
 * the request, send it, map HTTP errors to ThreatIntelException, parse the body) and the
 * subclasses supply the service-specific parts: {@link #buildRequest} and {@link #parseScore},
 * plus {@link #notFound} for services that answer 404 for indicators they have never seen.
 */
public abstract class RestIntelAdapter implements ThreatIntelProvider {

    static final Duration TIMEOUT = Duration.ofSeconds(10);

    protected final String baseUrl;
    protected final String apiKey;
    private final HttpClient http;

    protected RestIntelAdapter(String baseUrl, String apiKey, HttpClient http) {
        String base = Objects.requireNonNull(baseUrl, "baseUrl").strip();
        while (base.endsWith("/")) {
            base = base.substring(0, base.length() - 1);
        }
        this.baseUrl = base;
        this.apiKey = Objects.requireNonNull(apiKey, "apiKey");
        this.http = http;
    }

    @Override
    public final IntelResult lookup(String type, String value) {
        if (!supports(type)) {
            throw new ThreatIntelException(name() + " cannot rate " + type + " indicators");
        }
        HttpResponse<String> response;
        try {
            response = http.send(buildRequest(type, value), HttpResponse.BodyHandlers.ofString());
        } catch (HttpTimeoutException e) {
            throw new ThreatIntelException("timeout after " + TIMEOUT.toSeconds() + " s", e);
        } catch (IOException e) {
            throw new ThreatIntelException("could not reach the service (" + e.getClass().getSimpleName() + ")", e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new ThreatIntelException("interrupted", e);
        }
        int status = response.statusCode();
        if (status == 401 || status == 403) {
            throw new ThreatIntelException("API key rejected (HTTP " + status + ")");
        }
        if (status == 429) {
            throw new ThreatIntelException("rate limit reached (HTTP 429)");
        }
        if (status == 404) {
            return notFound(type, value);
        }
        if (status / 100 != 2) {
            throw new ThreatIntelException("service error (HTTP " + status + ")");
        }
        try {
            return parseScore(response.body());
        } catch (RuntimeException e) {
            throw new ThreatIntelException("unexpected response", e);
        }
    }

    /** The service-specific request for one indicator. */
    protected abstract HttpRequest buildRequest(String type, String value);

    /** Converts the service's JSON answer into the common 0-100 score. */
    protected abstract IntelResult parseScore(String json);

    /** What a 404 means; by default an error. */
    protected IntelResult notFound(String type, String value) {
        throw new ThreatIntelException("not found (HTTP 404)");
    }

    /** A GET request with the standard timeout and JSON Accept header. */
    protected HttpRequest.Builder get(String url) {
        return HttpRequest.newBuilder(URI.create(url)).timeout(TIMEOUT).header("Accept", "application/json").GET();
    }

    protected static HttpClient defaultClient() {
        return HttpClient.newBuilder().connectTimeout(TIMEOUT).build();
    }

    @Override
    public String toString() {
        return name();
    }
}
