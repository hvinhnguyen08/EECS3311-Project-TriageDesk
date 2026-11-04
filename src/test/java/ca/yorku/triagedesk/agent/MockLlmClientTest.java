package ca.yorku.triagedesk.agent;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.junit.jupiter.api.Test;

class MockLlmClientTest {

    @Test
    void scriptedRepliesComeBackInOrderAndRequestsAreRecorded() {
        ToolCall call = new ToolCall("c1", "count_by", "{\"field\":\"srcIp\"}");
        MockLlmClient llm = new MockLlmClient(LlmReply.withToolCalls(call), LlmReply.text("final answer"));

        LlmReply first = llm.chat(List.of(ChatMessage.user("q")), List.of("{\"name\":\"count_by\"}"));
        LlmReply second = llm.chat(List.of(ChatMessage.user("q"), ChatMessage.toolResult(call, "{}")), List.of());

        assertTrue(first.hasToolCall());
        assertEquals("final answer", second.text());
        assertEquals(2, llm.getRequests().size());
        assertEquals(2, llm.getRequests().get(1).size());
        assertEquals(List.of("{\"name\":\"count_by\"}"), llm.getToolSpecs().get(0));
        assertEquals(0, llm.remainingScriptedReplies());
        assertThrows(LlmException.class, () -> llm.chat(List.of(ChatMessage.user("again")), List.of()));
    }

    @Test
    void responderAnswersAfterTheScript() {
        MockLlmClient llm = new MockLlmClient(
                messages -> LlmReply.text("seen " + messages.size() + " messages"), LlmReply.text("scripted"));

        assertEquals("scripted", llm.chat(List.of(ChatMessage.user("a")), List.of()).text());
        assertEquals("seen 2 messages", llm.chat(List.of(ChatMessage.system("s"), ChatMessage.user("a")), List.of()).text());
    }

    @Test
    void messageAndCallValidation() {
        assertThrows(IllegalArgumentException.class, () -> new ChatMessage(ChatMessage.TOOL, "x", null, null, null));
        assertEquals("{}", new ToolCall("id", "count_by", " ").argumentsJson());
        assertTrue(ChatMessage.assistantToolCalls(null, List.of(new ToolCall("i", "n", "{}"))).hasToolCalls());
        assertEquals("", LlmReply.text(null).text());
    }
}
