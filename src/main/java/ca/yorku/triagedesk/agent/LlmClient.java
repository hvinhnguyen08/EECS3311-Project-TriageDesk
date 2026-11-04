package ca.yorku.triagedesk.agent;

import java.util.List;

/**
 * Strategy interface for the language model. SocAgent talks only to this interface, so it
 * runs unchanged against a real OpenAI-compatible service or the scripted MockLlmClient.
 */
public interface LlmClient {

    /**
     * Sends the conversation and the tools the model may call.
     *
     * @param toolSpecs one JSON object per tool: {"name", "description", "parameters" (JSON Schema)}
     * @throws LlmException if the service cannot be reached or refuses the request
     */
    LlmReply chat(List<ChatMessage> messages, List<String> toolSpecs);

    /** Short description for logs and the GUI, for example "openai-compatible llama-3.3-70b-versatile". Never includes a key. */
    String describe();
}
