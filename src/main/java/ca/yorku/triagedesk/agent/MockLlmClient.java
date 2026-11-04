package ca.yorku.triagedesk.agent;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.function.Function;

/**
 * Concrete LlmClient that needs no network or key. It answers with scripted replies in
 * order, then (if given) with a responder function that looks at the conversation. It
 * records every request so tests can check what the agent sent.
 */
public class MockLlmClient implements LlmClient {

    private final Deque<LlmReply> scripted = new ArrayDeque<>();
    private final Function<List<ChatMessage>, LlmReply> responder;
    private final List<List<ChatMessage>> requests = new ArrayList<>();
    private final List<List<String>> toolSpecs = new ArrayList<>();

    /** Answers with these replies, in order; a further request is an error. */
    public MockLlmClient(LlmReply... replies) {
        this(null, replies);
    }

    /** Answers the scripted replies first, then asks the responder. */
    public MockLlmClient(Function<List<ChatMessage>, LlmReply> responder, LlmReply... replies) {
        this.responder = responder;
        scripted.addAll(List.of(replies));
    }

    public synchronized MockLlmClient add(LlmReply reply) {
        scripted.add(reply);
        return this;
    }

    @Override
    public synchronized LlmReply chat(List<ChatMessage> messages, List<String> specs) {
        requests.add(List.copyOf(messages));
        toolSpecs.add(specs == null ? List.of() : List.copyOf(specs));
        if (!scripted.isEmpty()) {
            return scripted.poll();
        }
        if (responder != null) {
            return responder.apply(List.copyOf(messages));
        }
        throw new LlmException("Mock LLM has no scripted reply left");
    }

    @Override
    public String describe() {
        return "mock (offline, scripted replies)";
    }

    /** Every conversation sent so far, oldest first. */
    public synchronized List<List<ChatMessage>> getRequests() {
        return List.copyOf(requests);
    }

    /** The tool specs sent with each request, in the same order as {@link #getRequests()}. */
    public synchronized List<List<String>> getToolSpecs() {
        return List.copyOf(toolSpecs);
    }

    public synchronized int remainingScriptedReplies() {
        return scripted.size();
    }
}
