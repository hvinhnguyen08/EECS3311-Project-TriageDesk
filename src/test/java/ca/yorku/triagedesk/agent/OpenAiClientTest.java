package ca.yorku.triagedesk.agent;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ca.yorku.triagedesk.config.AppConfig;
import ca.yorku.triagedesk.util.Json;
import com.fasterxml.jackson.databind.JsonNode;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** Runs the client against a local fake chat-completions server: no network or key needed. */
class OpenAiClientTest {

    private static final String SPEC = "{\"name\":\"count_by\",\"description\":\"Count events\","
            + "\"parameters\":{\"type\":\"object\",\"properties\":{\"field\":{\"type\":\"string\"}},\"required\":[\"field\"]}}";

    private HttpServer server;
    private final AtomicReference<String> lastBody = new AtomicReference<>();
    private final AtomicReference<String> lastAuth = new AtomicReference<>();
    private final AtomicReference<String> lastPath = new AtomicReference<>();
    private volatile int status = 200;
    private volatile String response = "{}";

    @BeforeEach
    void startServer() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            lastPath.set(exchange.getRequestURI().getPath());
            lastAuth.set(exchange.getRequestHeaders().getFirst("Authorization"));
            lastBody.set(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            byte[] bytes = response.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(status, bytes.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(bytes);
            }
        });
        server.start();
    }

    @AfterEach
    void stopServer() {
        server.stop(0);
    }

    private String baseUrl() {
        return "http://127.0.0.1:" + server.getAddress().getPort() + "/v1/";
    }

    private OpenAiClient client() {
        return new OpenAiClient(baseUrl(), "sk-test-key", "test-model", Duration.ofSeconds(5));
    }

    @Test
    void sendsTheConversationAndToolsInOpenAiFormat() throws IOException {
        response = "{\"choices\":[{\"message\":{\"role\":\"assistant\",\"content\":\"done\"}}]}";
        ToolCall call = new ToolCall("call_1", "count_by", "{\"field\":\"srcIp\"}");

        client().chat(List.of(
                ChatMessage.system("You are a SOC analyst."),
                ChatMessage.user("Who failed to log in?"),
                ChatMessage.assistantToolCalls(null, List.of(call)),
                ChatMessage.toolResult(call, "{\"203.0.113.7\":13}")), List.of(SPEC));

        assertEquals("/v1/chat/completions", lastPath.get());
        assertEquals("Bearer sk-test-key", lastAuth.get());
        JsonNode body = Json.mapper().readTree(lastBody.get());
        assertEquals("test-model", body.path("model").asText());
        JsonNode msgs = body.path("messages");
        assertEquals(4, msgs.size());
        assertEquals("system", msgs.get(0).path("role").asText());
        assertTrue(msgs.get(2).path("content").isNull());
        assertEquals("count_by", msgs.get(2).path("tool_calls").get(0).path("function").path("name").asText());
        assertEquals("{\"field\":\"srcIp\"}", msgs.get(2).path("tool_calls").get(0).path("function").path("arguments").asText());
        assertEquals("tool", msgs.get(3).path("role").asText());
        assertEquals("call_1", msgs.get(3).path("tool_call_id").asText());
        assertEquals("function", body.path("tools").get(0).path("type").asText());
        assertEquals("count_by", body.path("tools").get(0).path("function").path("name").asText());
        assertEquals("auto", body.path("tool_choice").asText());
    }

    @Test
    void noToolsMeansNoToolsField() throws IOException {
        response = "{\"choices\":[{\"message\":{\"content\":\"hi\"}}]}";

        client().chat(List.of(ChatMessage.user("hello")), List.of());

        assertFalse(Json.mapper().readTree(lastBody.get()).has("tools"));
    }

    @Test
    void parsesATextReplyWithUsage() {
        response = "{\"choices\":[{\"message\":{\"content\":\"Looks like a brute force.\"}}],"
                + "\"usage\":{\"prompt_tokens\":120,\"completion_tokens\":8}}";

        LlmReply reply = client().chat(List.of(ChatMessage.user("?")), List.of());

        assertEquals("Looks like a brute force.", reply.text());
        assertFalse(reply.hasToolCall());
        assertEquals(120, reply.promptTokens());
        assertEquals(8, reply.completionTokens());
    }

    @Test
    void parsesSeveralToolCalls() {
        response = "{\"choices\":[{\"message\":{\"content\":null,\"tool_calls\":["
                + "{\"id\":\"a\",\"type\":\"function\",\"function\":{\"name\":\"count_by\",\"arguments\":\"{\\\"field\\\":\\\"user\\\"}\"}},"
                + "{\"type\":\"function\",\"function\":{\"name\":\"search_events\",\"arguments\":{\"srcIp\":\"203.0.113.7\"}}}"
                + "]}}]}";

        LlmReply reply = client().chat(List.of(ChatMessage.user("?")), List.of(SPEC));

        assertEquals("", reply.text());
        assertEquals(2, reply.toolCalls().size());
        assertEquals(new ToolCall("a", "count_by", "{\"field\":\"user\"}"), reply.toolCalls().get(0));
        assertEquals("call_1", reply.toolCalls().get(1).id(), "missing IDs are generated");
        assertEquals("{\"srcIp\":\"203.0.113.7\"}", reply.toolCalls().get(1).argumentsJson(), "object arguments are accepted");
    }

    @Test
    void httpErrorsBecomeReadableLlmExceptions() {
        status = 401;
        response = "{\"error\":{\"message\":\"Invalid API Key\"}}";
        LlmException auth = assertThrows(LlmException.class, () -> client().chat(List.of(ChatMessage.user("?")), List.of()));
        assertTrue(auth.getMessage().contains("rejected the API key"), auth.getMessage());
        assertFalse(auth.getMessage().contains("sk-test-key"));

        status = 429;
        response = "{\"error\":{\"message\":\"Rate limit reached for model\"}}";
        LlmException rate = assertThrows(LlmException.class, () -> client().chat(List.of(ChatMessage.user("?")), List.of()));
        assertTrue(rate.getMessage().contains("rate limit") && rate.getMessage().contains("Rate limit reached for model"));

        status = 500;
        response = "oops";
        LlmException server500 = assertThrows(LlmException.class, () -> client().chat(List.of(ChatMessage.user("?")), List.of()));
        assertEquals("AI service unavailable (HTTP 500)", server500.getMessage());

        status = 200;
        response = "not json";
        assertThrows(LlmException.class, () -> client().chat(List.of(ChatMessage.user("?")), List.of()));
        response = "{\"choices\":[]}";
        assertThrows(LlmException.class, () -> client().chat(List.of(ChatMessage.user("?")), List.of()));
    }

    @Test
    void unreachableServiceIsReportedAsUnavailable() {
        OpenAiClient client = client();
        server.stop(0);

        LlmException e = assertThrows(LlmException.class, () -> client.chat(List.of(ChatMessage.user("?")), List.of()));

        assertTrue(e.getMessage().startsWith("AI service unavailable: could not reach 127.0.0.1"), e.getMessage());
    }

    @Test
    void configNeedsAKeyExceptForALocalServer() {
        IllegalStateException missing = assertThrows(IllegalStateException.class, () -> OpenAiClient.fromConfig(
                AppConfig.load(null, Map.of("LLM_BASE_URL", "https://api.groq.com/openai/v1"))));
        assertTrue(missing.getMessage().contains("LLM_API_KEY is not set"));

        OpenAiClient ollama = OpenAiClient.fromConfig(AppConfig.load(null, Map.of(
                "LLM_BASE_URL", "http://localhost:11434/v1", "LLM_MODEL", "llama3.1:8b")));
        assertEquals("openai-compatible llama3.1:8b at localhost", ollama.describe());
    }

    @Test
    void describeNeverShowsTheKey() {
        assertFalse(client().describe().contains("sk-test-key"));
        assertFalse(client().toString().contains("sk-test-key"));
    }

    @Test
    void invalidToolSpecIsRejectedBeforeSending() {
        assertThrows(IllegalArgumentException.class,
                () -> client().requestBody(List.of(ChatMessage.user("?")), List.of("{not json")));
    }
}
