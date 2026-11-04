package ca.yorku.triagedesk.agent;

import ca.yorku.triagedesk.config.AppConfig;

/** Chooses the LlmClient strategy from LLM_PROVIDER. */
public final class LlmClients {

    private LlmClients() {
    }

    /**
     * "mock" gives the offline MockLlmClient; anything else gives an OpenAiClient for LLM_BASE_URL.
     *
     * @throws IllegalStateException if a real service is configured without a key
     */
    public static LlmClient create(AppConfig config) {
        if (config.useMockLlm()) {
            return new MockLlmClient(new OfflineResponder());
        }
        return OpenAiClient.fromConfig(config);
    }
}
