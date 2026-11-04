package ca.yorku.triagedesk.agent;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ca.yorku.triagedesk.domain.AgentResult;
import ca.yorku.triagedesk.ingest.EventStore;
import ca.yorku.triagedesk.testutil.SampleData;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class SocAgentLoopTest {

    private static final List<String> BOTH = List.of(SearchEventsTool.NAME, CountByTool.NAME);

    @TempDir
    Path dataDir;

    private ToolRegistry tools;

    @BeforeEach
    void setUp() {
        EventStore store = new EventStore(dataDir);
        store.addEvents(SampleData.all());
        tools = new ToolRegistry().register(new SearchEventsTool(store)).register(new CountByTool(store));
    }

    private static ToolCall call(String id, String name, String args) {
        return new ToolCall(id, name, args);
    }

    @Test
    void directAnswerNeedsNoTools() {
        MockLlmClient llm = new MockLlmClient(LlmReply.text("Nothing to check."));

        AgentResult r = new SocAgent(llm, tools, 6).runLoop("system", "hello", List.of(CountByTool.NAME));

        assertEquals("Nothing to check.", r.text());
        assertEquals(List.of(), r.toolTrace());
        assertFalse(r.stoppedEarly());
        assertEquals(1, llm.getToolSpecs().get(0).size(), "only the allowed tool is offered");
        assertTrue(llm.getToolSpecs().get(0).get(0).contains("\"name\":\"count_by\""));
    }

    @Test
    void toolResultsAreSentBackToTheModel() {
        ToolCall count = call("c1", CountByTool.NAME, "{\"field\":\"srcIp\",\"category\":\"auth_failure\",\"source\":\"auth\"}");
        MockLlmClient llm = new MockLlmClient(LlmReply.withToolCalls(count), LlmReply.text("203.0.113.7 failed 13 times."));

        AgentResult r = new SocAgent(llm, tools, 6).runLoop("system", "Which IP failed most?", BOTH);

        assertEquals("203.0.113.7 failed 13 times.", r.text());
        assertEquals(1, r.toolTrace().size());
        assertTrue(r.toolTrace().get(0).startsWith("count_by {\"field\":\"srcIp\""), r.toolTrace().get(0));
        assertTrue(r.toolTrace().get(0).contains("-> {\"field\":\"srcIp\",\"eventsCounted\":17"), r.toolTrace().get(0));

        List<ChatMessage> second = llm.getRequests().get(1);
        assertEquals(4, second.size());
        assertEquals(ChatMessage.SYSTEM, second.get(0).role());
        assertEquals(ChatMessage.USER, second.get(1).role());
        assertEquals(count, second.get(2).toolCalls().get(0));
        assertEquals("c1", second.get(3).toolCallId());
        assertTrue(second.get(3).content().contains("\"203.0.113.7\":13"));
    }

    @Test
    void severalToolCallsInOneStepRunInOrder() {
        MockLlmClient llm = new MockLlmClient(
                LlmReply.withToolCalls(
                        call("a", CountByTool.NAME, "{\"field\":\"user\",\"srcIp\":\"203.0.113.7\"}"),
                        call("b", SearchEventsTool.NAME, "{\"srcIp\":\"203.0.113.7\",\"category\":\"auth_success\"}")),
                LlmReply.text("deploy logged in after the failures."));

        AgentResult r = new SocAgent(llm, tools, 6).runLoop("s", "p", BOTH);

        assertEquals(2, r.toolTrace().size());
        List<ChatMessage> second = llm.getRequests().get(1);
        assertEquals("a", second.get(3).toolCallId());
        assertEquals("b", second.get(4).toolCallId());
        assertTrue(second.get(4).content().contains("Accepted password for deploy"));
    }

    @Test
    void toolErrorsAreReturnedToTheModelAndTheLoopContinues() {
        MockLlmClient llm = new MockLlmClient(
                LlmReply.withToolCalls(call("a", SearchEventsTool.NAME, "{\"ip\":\"203.0.113.7\"}")),
                LlmReply.withToolCalls(call("b", "delete_everything", "{}")),
                LlmReply.withToolCalls(call("c", CountByTool.NAME, "{\"field\":\"srcIp\"}")),
                LlmReply.text("done"));

        AgentResult r = new SocAgent(llm, tools, 6).runLoop("s", "p", List.of(CountByTool.NAME, SearchEventsTool.NAME));

        assertEquals("done", r.text());
        List<ChatMessage> last = llm.getRequests().get(3);
        assertTrue(last.get(3).content().startsWith("ERROR: Unknown search criterion 'ip'"), last.get(3).content());
        assertTrue(last.get(5).content().startsWith("ERROR: tool 'delete_everything' is not available"));
        assertTrue(last.get(7).content().startsWith("{\"field\":\"srcIp\""));
    }

    @Test
    void aToolThatIsRegisteredButNotAllowedIsRefused() {
        MockLlmClient llm = new MockLlmClient(
                LlmReply.withToolCalls(call("a", SearchEventsTool.NAME, "{}")), LlmReply.text("ok"));

        new SocAgent(llm, tools, 6).runLoop("s", "p", List.of(CountByTool.NAME));

        assertTrue(llm.getRequests().get(1).get(3).content().startsWith("ERROR: tool 'search_events' is not available"));
    }

    @Test
    void stepLimitAsksForAFinalAnswerWithoutTools() {
        MockLlmClient llm = new MockLlmClient(
                LlmReply.withToolCalls(call("1", CountByTool.NAME, "{\"field\":\"srcIp\"}")),
                LlmReply.withToolCalls(call("2", CountByTool.NAME, "{\"field\":\"user\"}")),
                LlmReply.text("Partial answer."));

        AgentResult r = new SocAgent(llm, tools, 2).runLoop("s", "p", BOTH);

        assertTrue(r.stoppedEarly());
        assertEquals("Partial answer.", r.text());
        assertEquals(2, r.toolTrace().size());
        assertEquals(3, llm.getRequests().size());
        assertEquals(List.of(), llm.getToolSpecs().get(2), "no tools on the final call");
        List<ChatMessage> finalRequest = llm.getRequests().get(2);
        assertEquals(SocAgent.STEP_LIMIT_PROMPT, finalRequest.get(finalRequest.size() - 1).content());
    }

    @Test
    void longToolResultsAreTruncated() {
        Tool huge = new Tool() {
            public String name() { return "huge"; }
            public String description() { return "returns a lot"; }
            public String parameters() { return "{\"type\":\"object\",\"properties\":{}}"; }
            public String execute(String argsJson) { return "x".repeat(20_000); }
        };
        tools.register(huge);
        MockLlmClient llm = new MockLlmClient(LlmReply.withToolCalls(call("h", "huge", "{}")), LlmReply.text("ok"));

        new SocAgent(llm, tools, 6).runLoop("s", "p", List.of("huge"));

        String sent = llm.getRequests().get(1).get(3).content();
        assertTrue(sent.length() < SocAgent.MAX_TOOL_RESULT_CHARS + 100);
        assertTrue(sent.endsWith("[truncated: use filters or a smaller limit]"));
    }

    @Test
    void modelFailurePropagates() {
        MockLlmClient llm = new MockLlmClient();

        assertThrows(LlmException.class, () -> new SocAgent(llm, tools, 6).runLoop("s", "p", BOTH));
        assertThrows(IllegalArgumentException.class, () -> new SocAgent(llm, tools, 0));
    }
}
