package ca.yorku.triagedesk.config;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.DateTimeException;
import java.time.Duration;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Application settings. Values come from a local .env file, and real environment
 * variables override the file. API keys are never hard-coded or printed.
 */
public final class AppConfig {

    public static final String PLACEHOLDER_KEY = "YOUR_LOCAL_API_KEY_HERE";

    private final String llmProvider;
    private final String llmBaseUrl;
    private final String llmApiKey;
    private final String llmModel;
    private final int llmMaxSteps;
    private final Duration llmTimeout;
    private final String abuseIpDbApiKey;
    private final String virusTotalApiKey;
    private final Path dataDir;
    private final ZoneId logTimeZone;
    private final int wazuhMinLevel;
    private final int bruteForceThreshold;
    private final Duration bruteForceWindow;
    private final int successAfterFailureMinFailures;
    private final Duration successAfterFailureWindow;
    private final int webScanThreshold;
    private final Duration webScanWindow;

    private AppConfig(Map<String, String> values) {
        this.llmProvider = values.getOrDefault("LLM_PROVIDER", "mock").trim().toLowerCase();
        this.llmBaseUrl = values.getOrDefault("LLM_BASE_URL", "https://api.openai.com/v1").trim();
        this.llmApiKey = cleanKey(values.get("LLM_API_KEY"));
        this.llmModel = values.getOrDefault("LLM_MODEL", "gpt-4o-mini").trim();
        this.llmMaxSteps = parsePositiveInt(values.get("LLM_MAX_STEPS"), 6);
        this.llmTimeout = Duration.ofSeconds(parsePositiveInt(values.get("LLM_TIMEOUT_SECONDS"), 60));
        this.abuseIpDbApiKey = cleanKey(values.get("ABUSEIPDB_API_KEY"));
        this.virusTotalApiKey = cleanKey(values.get("VIRUSTOTAL_API_KEY"));
        this.dataDir = Path.of(values.getOrDefault("TRIAGEDESK_DATA_DIR", "./data").trim());
        this.logTimeZone = parseZone(values.get("LOG_TIMEZONE"));
        this.wazuhMinLevel = parsePositiveInt(values.get("DETECT_WAZUH_MIN_LEVEL"), 7);
        this.bruteForceThreshold = parsePositiveInt(values.get("DETECT_BRUTE_FORCE_THRESHOLD"), 10);
        this.bruteForceWindow = Duration.ofMinutes(parsePositiveInt(values.get("DETECT_BRUTE_FORCE_WINDOW_MINUTES"), 5));
        this.successAfterFailureMinFailures = parsePositiveInt(values.get("DETECT_SUCCESS_AFTER_FAILURE_MIN_FAILURES"), 5);
        this.successAfterFailureWindow = Duration.ofMinutes(
                parsePositiveInt(values.get("DETECT_SUCCESS_AFTER_FAILURE_WINDOW_MINUTES"), 10));
        this.webScanThreshold = parsePositiveInt(values.get("DETECT_WEB_SCAN_THRESHOLD"), 30);
        this.webScanWindow = Duration.ofMinutes(parsePositiveInt(values.get("DETECT_WEB_SCAN_WINDOW_MINUTES"), 2));
    }

    /** Loads ./.env (if present) and the process environment. */
    public static AppConfig load() {
        return load(Path.of(".env"), System.getenv());
    }

    /** Loads the given env file (if present); entries in {@code environment} take precedence. */
    public static AppConfig load(Path envFile, Map<String, String> environment) {
        Map<String, String> values = new HashMap<>();
        if (envFile != null && Files.isRegularFile(envFile)) {
            try {
                values.putAll(parseEnvFile(Files.readAllLines(envFile, StandardCharsets.UTF_8)));
            } catch (IOException e) {
                throw new UncheckedIOException("Could not read " + envFile, e);
            }
        }
        environment.forEach((k, v) -> {
            if (v != null && !v.isBlank()) {
                values.put(k, v);
            }
        });
        return new AppConfig(values);
    }

    /** Parses KEY=VALUE lines; ignores blank lines and # comments, strips matching quotes. */
    static Map<String, String> parseEnvFile(List<String> lines) {
        Map<String, String> values = new HashMap<>();
        for (String raw : lines) {
            String line = raw.strip();
            if (line.isEmpty() || line.startsWith("#")) {
                continue;
            }
            if (line.startsWith("export ")) {
                line = line.substring("export ".length()).strip();
            }
            int eq = line.indexOf('=');
            if (eq <= 0) {
                continue;
            }
            String key = line.substring(0, eq).strip();
            String value = line.substring(eq + 1).strip();
            if (value.length() >= 2
                    && (value.startsWith("\"") && value.endsWith("\"")
                        || value.startsWith("'") && value.endsWith("'"))) {
                value = value.substring(1, value.length() - 1);
            } else {
                int comment = value.indexOf(" #");
                if (comment >= 0) {
                    value = value.substring(0, comment).strip();
                }
            }
            values.put(key, value);
        }
        return values;
    }

    private static String cleanKey(String key) {
        if (key == null || key.isBlank() || key.strip().equals(PLACEHOLDER_KEY)) {
            return null;
        }
        return key.strip();
    }

    /** Syslog lines carry no time zone; servers usually log in UTC, so UTC is the default. */
    private static ZoneId parseZone(String value) {
        if (value == null || value.isBlank()) {
            return ZoneOffset.UTC;
        }
        try {
            return ZoneId.of(value.strip());
        } catch (DateTimeException e) {
            throw new IllegalArgumentException("LOG_TIMEZONE is not a valid time zone: " + value
                    + " (examples: UTC, America/Toronto)");
        }
    }

    private static int parsePositiveInt(String value, int fallback) {
        if (value == null || value.isBlank()) {
            return fallback;
        }
        try {
            int n = Integer.parseInt(value.strip());
            return n > 0 ? n : fallback;
        } catch (NumberFormatException e) {
            return fallback;
        }
    }

    public String getLlmProvider() { return llmProvider; }
    public String getLlmBaseUrl() { return llmBaseUrl; }
    public String getLlmApiKey() { return llmApiKey; }
    public String getLlmModel() { return llmModel; }
    public int getLlmMaxSteps() { return llmMaxSteps; }
    public Duration getLlmTimeout() { return llmTimeout; }
    public String getAbuseIpDbApiKey() { return abuseIpDbApiKey; }
    public String getVirusTotalApiKey() { return virusTotalApiKey; }
    public Path getDataDir() { return dataDir; }
    public ZoneId getLogTimeZone() { return logTimeZone; }
    public int getWazuhMinLevel() { return wazuhMinLevel; }
    public int getBruteForceThreshold() { return bruteForceThreshold; }
    public Duration getBruteForceWindow() { return bruteForceWindow; }
    public int getSuccessAfterFailureMinFailures() { return successAfterFailureMinFailures; }
    public Duration getSuccessAfterFailureWindow() { return successAfterFailureWindow; }
    public int getWebScanThreshold() { return webScanThreshold; }
    public Duration getWebScanWindow() { return webScanWindow; }

    public boolean hasLlmKey() { return llmApiKey != null; }
    public boolean useMockLlm() { return llmProvider.equals("mock"); }

    @Override
    public String toString() {
        return "AppConfig{provider=" + llmProvider
                + ", baseUrl=" + llmBaseUrl
                + ", model=" + llmModel
                + ", maxSteps=" + llmMaxSteps
                + ", llmKey=" + (hasLlmKey() ? "set" : "missing")
                + ", abuseIpDbKey=" + (abuseIpDbApiKey != null ? "set" : "missing")
                + ", virusTotalKey=" + (virusTotalApiKey != null ? "set" : "missing")
                + ", dataDir=" + dataDir + "}";
    }
}
