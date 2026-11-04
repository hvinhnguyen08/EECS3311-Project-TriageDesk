package ca.yorku.triagedesk.facade;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ca.yorku.triagedesk.agent.LlmReply;
import ca.yorku.triagedesk.agent.MockLlmClient;
import ca.yorku.triagedesk.agent.ToolCall;
import ca.yorku.triagedesk.config.AppConfig;
import ca.yorku.triagedesk.domain.Ioc;
import ca.yorku.triagedesk.intel.EnrichmentService;
import ca.yorku.triagedesk.intel.IntelResult;
import ca.yorku.triagedesk.intel.ThreatIntelProvider;
import java.nio.file.Path;
import java.time.Clock;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class SocAssistantEnrichTest {

    private static final AppConfig CONFIG = AppConfig.load(null, Map.of());

    @TempDir
    Path dataDir;

    private static final ThreatIntelProvider FAKE_VT = new ThreatIntelProvider() {
        public String name() { return "FakeTI"; }
        public boolean supports(String type) { return true; }
        public IntelResult lookup(String type, String value) {
            return new IntelResult(value.equals("203.0.113.7") ? 92 : 0, "fake");
        }
    };

    private SocAssistant assistant(MockLlmClient llm) {
        SocAssistant a = SocAssistant.create(CONFIG, dataDir, llm,
                new EnrichmentService(List.of(FAKE_VT), dataDir, Clock.systemUTC()));
        a.importFile(Path.of("samples/alerts.json"));
        a.importFile(Path.of("samples/auth.log"));
        a.importFile(Path.of("samples/access.log"));
        a.runDetections();
        return a;
    }

    @Test
    void enrichmentIsSavedOnTheCase() {
        SocAssistant a = assistant(new MockLlmClient());

        List<Ioc> iocs = a.enrichIocs("CASE-0001");

        assertEquals(2, iocs.size());
        assertEquals(92, iocs.get(0).score());
        assertEquals(List.of("FakeTI"), a.threatIntelProviders());
        SocAssistant restarted = SocAssistant.create(CONFIG, dataDir, new MockLlmClient());
        assertEquals(iocs, restarted.getCase("CASE-0001").getIocs());
        assertTrue(a.enrichIocs("CASE-0003").isEmpty(), "the rootkit alert has no indicators");
    }

    @Test
    void theAgentCanLookUpReputationsDuringTriage() {
        MockLlmClient llm = new MockLlmClient(
                LlmReply.withToolCalls(new ToolCall("c1", "lookup_ioc", "{\"value\":\"203.0.113.7\"}")),
                LlmReply.text("{\"verdict\":\"TRUE_POSITIVE\",\"confidence\":0.95,\"reasoning\":\"Known bad IP.\"}"));
        SocAssistant a = assistant(llm);

        a.triageCase("CASE-0001");

        assertTrue(llm.getToolSpecs().get(0).stream().anyMatch(s -> s.contains("\"name\":\"lookup_ioc\"")));
        String toolResult = llm.getRequests().get(1).get(3).content();
        assertEquals("{\"type\":\"ip\",\"value\":\"203.0.113.7\",\"score\":92,\"source\":\"FakeTI: fake\"}", toolResult);
    }

    @Test
    void withoutKeysIndicatorsAreListedUnscored() {
        SocAssistant a = SocAssistant.create(CONFIG, dataDir, new MockLlmClient());
        a.importFile(Path.of("samples/auth.log"));
        a.runDetections();

        List<Ioc> iocs = a.enrichIocs("CASE-0001");

        assertEquals(List.of(), a.threatIntelProviders());
        assertEquals("203.0.113.7", iocs.get(0).value());
        assertFalse(iocs.get(0).isScored());
    }
}
