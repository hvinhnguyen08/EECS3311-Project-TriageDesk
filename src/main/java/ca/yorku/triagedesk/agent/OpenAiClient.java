package ca.yorku.triagedesk.agent;

import ca.yorku.triagedesk.config.AppConfig;
import ca.yorku.triagedesk.util.Json;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/**
 * Concrete LlmClient for any service with the OpenAI chat-completions API and function
 * calling: OpenAI, Groq, OpenRouter, or a local Ollama server. Only the base URL, key and
 * model name differ, and they come from the configuration.
 */
public class OpenAiClient implements LlmClient {

    private static final double TEMPERATURE = 0.2;

    private final URI endpoint;
    private final String apiKey;
    private final String model;
    private final Duration timeout;
    private final HttpClient http;
    private final ObjectMapper mapper = Json.mapper();

    public OpenAiClient(String baseUrl, String apiKey, String model, Duration timeout) {
        this(baseUrl, apiKey, model, timeout,
                HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build());
    }

    OpenAiClient(String baseUrl, String apiKey, String model, Duration timeout, HttpClient http) {
        String base = baseUrl.strip();
        while (base.endsWith("/")) {
            base = base.substring(0, base.length() - 1);
        }
        this.endpoint = URI.create(base + "/chat/completions");
        this.apiKey = apiKey;
        this.model = model;
        this.timeout = timeout;
        this.http = http;
    }

    /**
     * Creates the client from LLM_BASE_URL, LLM_API_KEY and LLM_MODEL. A key is required
     * unless the service runs on this machine (Ollama).
     */
    public static OpenAiClient fromConfig(AppConfig config) {
        URI base = URI.create(config.getLlmBaseUrl());
        if (!config.hasLlmKey() && !isLocal(base)) {
            throw new IllegalStateException("LLM_API_KEY is not set. Copy .env.example to .env and add your key,"
                    + " or set LLM_PROVIDER=mock to run without an AI service.");
        }
        return new OpenAiClient(config.getLlmBaseUrl(), config.getLlmApiKey(), config.getLlmModel(),
                config.getLlmTimeout());
    }

    static boolean isLocal(URI uri) {
        String host = uri.getHost();
        return host != null && (host.equals("localhost") || host.equals("127.0.0.1") || host.equals("[::1]"));
    }

    @Override
    public LlmReply chat(List<ChatMessage> messages, List<String> toolSpecs) {
        HttpRequest.Builder request = HttpRequest.newBuilder(endpoint)
                .timeout(timeout)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(requestBody(messages, toolSpecs)));
        if (apiKey != null) {
            request.header("Authorization", "Bearer " + apiKey);
        }

        HttpResponse<String> response;
        try {
            response = http.send(request.build(), HttpResponse.BodyHandlers.ofString());
        } catch (HttpTimeoutException e) {
            throw new LlmException("AI service unavailable: no answer from " + endpoint.getHost()
                    + " within " + timeout.toSeconds() + " s", e);
        } catch (IOException e) {
            throw new LlmException("AI service unavailable: could not reach " + endpoint.getHost()
                    + " (" + e.getClass().getSimpleName() + ")", e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new LlmException("AI request was interrupted", e);
        }

        int status = response.statusCode();
        if (status == 401 || status == 403) {
            throw new LlmException("AI service rejected the API key (HTTP " + status + "). Check LLM_API_KEY in .env.");
        }
        if (status == 429) {
            if (isQuotaError(response.body())) {
                throw new LlmException("AI service account has no credits or quota left (HTTP 429)."
                        + " Add credits with your provider or switch LLM_BASE_URL/LLM_API_KEY to another service."
                        + errorDetail(response.body()));
            }
            throw new LlmException("AI service rate limit reached (HTTP 429). Wait a moment and try again."
                    + errorDetail(response.body()));
        }
        if (status / 100 != 2) {
            throw new LlmException("AI service unavailable (HTTP " + status + ")" + errorDetail(response.body()));
        }
        return parseReply(response.body());
    }

    @Override
    public String describe() {
        return "openai-compatible " + model + " at " + endpoint.getHost();
    }

    /** Builds the chat-completions request JSON. */
    String requestBody(List<ChatMessage> messages, List<String> toolSpecs) {
        ObjectNode body = mapper.createObjectNode();
        body.put("model", model);
        body.put("temperature", TEMPERATURE);
        ArrayNode msgs = body.putArray("messages");
        for (ChatMessage m : messages) {
            ObjectNode node = msgs.addObject();
            node.put("role", m.role());
            if (m.content() == null) {
                node.putNull("content");
            } else {
                node.put("content", m.content());
            }
            if (m.hasToolCalls()) {
                ArrayNode calls = node.putArray("tool_calls");
                for (ToolCall c : m.toolCalls()) {
                    ObjectNode call = calls.addObject();
                    call.put("id", c.id());
                    call.put("type", "function");
                    ObjectNode fn = call.putObject("function");
                    fn.put("name", c.name());
                    fn.put("arguments", c.argumentsJson());
                }
            }
            if (m.toolCallId() != null) {
                node.put("tool_call_id", m.toolCallId());
            }
        }
        if (toolSpecs != null && !toolSpecs.isEmpty()) {
            ArrayNode tools = body.putArray("tools");
            for (String spec : toolSpecs) {
                ObjectNode tool = tools.addObject();
                tool.put("type", "function");
                try {
                    tool.set("function", mapper.readTree(spec));
                } catch (JsonProcessingException e) {
                    throw new IllegalArgumentException("Tool spec is not valid JSON: " + spec, e);
                }
            }
            body.put("tool_choice", "auto");
        }
        return body.toString();
    }

    /** Reads choices[0].message: its text and tool calls, plus the token usage if reported. */
    LlmReply parseReply(String json) {
        JsonNode root;
        try {
            root = mapper.readTree(json);
        } catch (JsonProcessingException e) {
            throw new LlmException("AI service returned a response that is not JSON", e);
        }
        JsonNode message = root.path("choices").path(0).path("message");
        if (message.isMissingNode()) {
            throw new LlmException("AI service returned an unexpected response (no choices)");
        }
        String text = message.path("content").isTextual() ? message.path("content").asText() : "";
        List<ToolCall> calls = new ArrayList<>();
        JsonNode toolCalls = message.path("tool_calls");
        for (int i = 0; i < toolCalls.size(); i++) {
            JsonNode c = toolCalls.get(i);
            JsonNode fn = c.path("function");
            JsonNode args = fn.path("arguments");
            String argsJson = args.isTextual() ? args.asText() : args.isMissingNode() ? "{}" : args.toString();
            String id = c.path("id").asText("");
            calls.add(new ToolCall(id.isEmpty() ? "call_" + i : id, fn.path("name").asText(), argsJson));
        }
        JsonNode usage = root.path("usage");
        return new LlmReply(text, calls, usage.path("prompt_tokens").asInt(0), usage.path("completion_tokens").asInt(0));
    }

    /** OpenAI uses HTTP 429 both for rate limits and for an account without credits ("insufficient_quota"). */
    private boolean isQuotaError(String body) {
        try {
            JsonNode error = mapper.readTree(body).path("error");
            String code = error.path("code").asText("") + " " + error.path("type").asText("");
            String msg = error.path("message").asText("").toLowerCase(java.util.Locale.ROOT);
            return code.contains("insufficient_quota") || msg.contains("credits") || msg.contains("exceeded your current quota");
        } catch (JsonProcessingException | RuntimeException e) {
            return false;
        }
    }

    private String errorDetail(String body) {
        try {
            String msg = mapper.readTree(body).path("error").path("message").asText("");
            if (msg.isEmpty()) {
                return "";
            }
            return ": " + (msg.length() > 200 ? msg.substring(0, 200) + "..." : msg);
        } catch (JsonProcessingException | RuntimeException e) {
            return "";
        }
    }

    @Override
    public String toString() {
        return describe();
    }
}
