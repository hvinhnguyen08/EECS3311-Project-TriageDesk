package ca.yorku.triagedesk.facade;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ca.yorku.triagedesk.agent.LlmReply;
import ca.yorku.triagedesk.agent.MockLlmClient;
import ca.yorku.triagedesk.attack.MappingResult;
import ca.yorku.triagedesk.config.AppConfig;
import ca.yorku.triagedesk.domain.AttackTechnique;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class SocAssistantAttackTest {

    private static final AppConfig CONFIG = AppConfig.load(null, Map.of());

    @TempDir
    Path dataDir;

    private SocAssistant assistant(MockLlmClient llm) {
        SocAssistant a = SocAssistant.create(CONFIG, dataDir, llm);
        a.importFile(Path.of("samples/alerts.json"));
        a.importFile(Path.of("samples/auth.log"));
        a.importFile(Path.of("samples/access.log"));
        a.runDetections();
        return a;
    }

    @Test
    void detectionTechniquesAreMappedAndSaved() {
        SocAssistant a = assistant(new MockLlmClient());

        MappingResult r = a.mapAttack("CASE-0001", false);

        assertEquals(List.of("T1110.001", "T1110", "T1078", "T1565.001"),
                r.techniques().stream().map(AttackTechnique::id).toList());
        SocAssistant restarted = SocAssistant.create(CONFIG, dataDir, new MockLlmClient());
        assertEquals(r.techniques(), restarted.getCase("CASE-0001").getTechniques());
    }

    @Test
    void theAgentCanAddTechniquesTheDetectionsMissed() {
        MockLlmClient llm = new MockLlmClient(LlmReply.text("{\"techniques\":[{\"id\":\"T1098.004\",\"reason\":\"authorized_keys"
                + " changed after the login\"},{\"id\":\"T1548.003\",\"reason\":\"denied sudo\"},{\"id\":\"T1999\",\"reason\":\"x\"}]}"));
        SocAssistant a = assistant(llm);

        MappingResult r = a.mapAttack("CASE-0001", true);

        assertEquals(List.of("T1098.004", "T1548.003"), r.fromAgent());
        assertEquals(List.of("T1999"), r.rejected());
        assertEquals(6, a.getCase("CASE-0001").getTechniques().size());
        List<String> offered = llm.getToolSpecs().get(0);
        assertEquals(2, offered.size(), "search_events and count_by, no reputation lookups");
        assertTrue(offered.stream().noneMatch(spec -> spec.contains("\"name\":\"lookup_ioc\"")));
        assertTrue(llm.getRequests().get(0).get(1).content().contains("\"caseId\":\"CASE-0001\""));
    }
}
