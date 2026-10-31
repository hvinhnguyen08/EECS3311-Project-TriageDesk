package ca.yorku.triagedesk.config;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class AppConfigTest {

    @TempDir
    Path dir;

    @Test
    void parsesKeyValuesCommentsAndQuotes() {
        Map<String, String> values = AppConfig.parseEnvFile(List.of(
                "# comment",
                "",
                "LLM_MODEL=llama-3.3-70b-versatile # trailing comment",
                "export LLM_PROVIDER=openai",
                "LLM_BASE_URL=\"http://localhost:11434/v1\"",
                "not a pair"));

        assertEquals("llama-3.3-70b-versatile", values.get("LLM_MODEL"));
        assertEquals("openai", values.get("LLM_PROVIDER"));
        assertEquals("http://localhost:11434/v1", values.get("LLM_BASE_URL"));
        assertEquals(3, values.size());
    }

    @Test
    void environmentOverridesFile() throws IOException {
        Path env = dir.resolve(".env");
        Files.writeString(env, "LLM_MODEL=from-file\nLLM_MAX_STEPS=4\n");

        AppConfig config = AppConfig.load(env, Map.of("LLM_MODEL", "from-env"));

        assertEquals("from-env", config.getLlmModel());
        assertEquals(4, config.getLlmMaxSteps());
    }

    @Test
    void defaultsWhenNothingIsConfigured() {
        AppConfig config = AppConfig.load(dir.resolve("missing.env"), Map.of());

        assertTrue(config.useMockLlm());
        assertFalse(config.hasLlmKey());
        assertEquals(6, config.getLlmMaxSteps());
        assertEquals(Path.of("./data"), config.getDataDir());
    }

    @Test
    void placeholderAndBlankKeysCountAsMissing() {
        AppConfig config = AppConfig.load(null, Map.of(
                "LLM_API_KEY", AppConfig.PLACEHOLDER_KEY,
                "ABUSEIPDB_API_KEY", "   "));

        assertFalse(config.hasLlmKey());
        assertNull(config.getAbuseIpDbApiKey());
    }

    @Test
    void invalidMaxStepsFallsBackToDefault() {
        assertEquals(6, AppConfig.load(null, Map.of("LLM_MAX_STEPS", "zero")).getLlmMaxSteps());
        assertEquals(6, AppConfig.load(null, Map.of("LLM_MAX_STEPS", "-2")).getLlmMaxSteps());
    }

    @Test
    void toStringNeverContainsTheKey() {
        AppConfig config = AppConfig.load(null, Map.of("LLM_API_KEY", "sk-secret-value"));

        assertTrue(config.hasLlmKey());
        assertFalse(config.toString().contains("sk-secret-value"));
    }
}
