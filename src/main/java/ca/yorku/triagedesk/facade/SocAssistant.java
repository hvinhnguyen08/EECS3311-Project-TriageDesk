package ca.yorku.triagedesk.facade;

import ca.yorku.triagedesk.agent.CountByTool;
import ca.yorku.triagedesk.agent.LlmClient;
import ca.yorku.triagedesk.agent.LlmClients;
import ca.yorku.triagedesk.agent.LlmException;
import ca.yorku.triagedesk.agent.LookupIocTool;
import ca.yorku.triagedesk.agent.SearchEventsTool;
import ca.yorku.triagedesk.agent.SocAgent;
import ca.yorku.triagedesk.agent.TokenUsage;
import ca.yorku.triagedesk.agent.ToolRegistry;
import ca.yorku.triagedesk.attack.AttackMapper;
import ca.yorku.triagedesk.attack.MappingResult;
import ca.yorku.triagedesk.casemgmt.CaseManager;
import ca.yorku.triagedesk.config.AppConfig;
import ca.yorku.triagedesk.detect.DetectionEngine;
import ca.yorku.triagedesk.domain.AgentResult;
import ca.yorku.triagedesk.domain.Case;
import ca.yorku.triagedesk.domain.DashboardStats;
import ca.yorku.triagedesk.domain.Finding;
import ca.yorku.triagedesk.domain.Ioc;
import ca.yorku.triagedesk.domain.SecurityEvent;
import ca.yorku.triagedesk.domain.TriageVerdict;
import ca.yorku.triagedesk.ingest.EventStore;
import ca.yorku.triagedesk.intel.EnrichmentService;
import ca.yorku.triagedesk.ingest.LogParser;
import ca.yorku.triagedesk.ingest.LogParserFactory;
import ca.yorku.triagedesk.ingest.UnsupportedFormatException;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;

/**
 * Facade over the TriageDesk subsystems: one method per feature, shared by the JavaFX
 * controllers and the CLI, so neither interface needs to know how parsing, detection,
 * case management (and later the agent) are wired together.
 */
public class SocAssistant {

    /** How many entries the dashboard's "top" lists show. */
    static final int TOP_N = 5;

    private final EventStore eventStore;
    private final LogParserFactory parserFactory;
    private final DetectionEngine detectionEngine;
    private final CaseManager caseManager;
    private final EnrichmentService enrichment;
    private final AttackMapper attackMapper;
    private final Supplier<SocAgent> agentFactory;
    private SocAgent agent;

    /**
     * @param agentFactory creates the agent on first use, so a missing API key only affects the AI features
     */
    public SocAssistant(EventStore eventStore, LogParserFactory parserFactory, DetectionEngine detectionEngine,
                        CaseManager caseManager, EnrichmentService enrichment, AttackMapper attackMapper,
                        Supplier<SocAgent> agentFactory) {
        this.eventStore = eventStore;
        this.parserFactory = parserFactory;
        this.detectionEngine = detectionEngine;
        this.caseManager = caseManager;
        this.enrichment = enrichment;
        this.attackMapper = attackMapper;
        this.agentFactory = agentFactory;
    }

    /** Builds the standard subsystems from the configuration and loads the saved events and cases. */
    public static SocAssistant create(AppConfig config) {
        return create(config, config.getDataDir());
    }

    /** Same as {@link #create(AppConfig)} but with an explicit data folder (CLI --data-dir option). */
    public static SocAssistant create(AppConfig config, Path dataDir) {
        return create(config, dataDir, () -> LlmClients.create(config), EnrichmentService.fromConfig(config, dataDir));
    }

    /** With a given model client, for tests and for choosing the client elsewhere. */
    public static SocAssistant create(AppConfig config, Path dataDir, LlmClient llm) {
        return create(config, dataDir, () -> llm, EnrichmentService.fromConfig(config, dataDir));
    }

    /** With a given model client and threat-intel service (tests use fake providers). */
    public static SocAssistant create(AppConfig config, Path dataDir, LlmClient llm, EnrichmentService enrichment) {
        return create(config, dataDir, () -> llm, enrichment);
    }

    private static SocAssistant create(AppConfig config, Path dataDir, Supplier<LlmClient> llm,
                                       EnrichmentService enrichment) {
        EventStore store = new EventStore(dataDir);
        store.load();
        CaseManager cases = new CaseManager(dataDir);
        cases.load();
        // The facade creates the agent's tools with their receivers and registers them (Stage 1, 4.7).
        ToolRegistry tools = new ToolRegistry()
                .register(new SearchEventsTool(store))
                .register(new CountByTool(store))
                .register(new LookupIocTool(enrichment));
        return new SocAssistant(store, new LogParserFactory(config.getLogTimeZone()),
                DetectionEngine.withStandardDetectors(config), cases, enrichment, AttackMapper.loadBundled(),
                () -> new SocAgent(llm.get(), tools, config.getLlmMaxSteps()));
    }

    // F01, F02: import a Wazuh alerts file or a raw log

    /**
     * Detects the format, parses the file and stores its events. Lines that cannot be
     * parsed are skipped and counted. Importing the same file again replaces its events.
     *
     * @throws IllegalArgumentException if the file does not exist or its format is not supported
     */
    public ImportResult importFile(Path path) {
        if (path == null || !Files.isRegularFile(path)) {
            throw new IllegalArgumentException("File not found: " + path);
        }
        List<String> lines;
        try {
            lines = LogParserFactory.readLines(path);
        } catch (IOException e) {
            throw new UncheckedIOException("Could not read " + path, e);
        }
        String format;
        try {
            format = parserFactory.detectFormat(lines);
        } catch (UnsupportedFormatException e) {
            throw new UnsupportedFormatException(path + ": Unsupported file format");
        }
        LogParser parser = parserFactory.createParser(format);
        String batchId = path.getFileName().toString();
        List<SecurityEvent> events = parser.parse(lines, batchId);
        int nonBlank = (int) lines.stream().filter(l -> !l.isBlank()).count();
        eventStore.addEvents(events);
        return new ImportResult(batchId, format, events.size(), nonBlank - events.size());
    }

    /** Imported files (batch IDs) in import order. */
    public List<String> listBatches() {
        return eventStore.batchIds();
    }

    // F03, F05: run the detectors and turn their findings into cases

    /** @throws IllegalStateException if nothing has been imported yet */
    public DetectionResult runDetections() {
        if (eventStore.size() == 0) {
            throw new IllegalStateException("Import a file first");
        }
        List<Finding> findings = detectionEngine.runAll(eventStore.all());
        List<Case> cases = caseManager.createCases(findings);
        List<String> warnings = new ArrayList<>(detectionEngine.getLastErrors());
        warnings.addAll(caseManager.getWarnings());
        return new DetectionResult(findings.size(), cases, warnings);
    }

    public List<Case> listCases() {
        return caseManager.listCases();
    }

    public Case getCase(String caseId) {
        return caseManager.getCase(caseId);
    }

    // F09: case lifecycle and notes

    /** start, escalate (comment = reason) or reopen. */
    public Case changeStatus(String caseId, String action, String comment) {
        return caseManager.applyAction(caseId, action, comment);
    }

    /** Any action; for close, {@code resolution} is true_positive, false_positive or benign. */
    public Case changeStatus(String caseId, String action, String resolution, String comment) {
        return caseManager.applyAction(caseId, action, resolution, comment);
    }

    public Case addNote(String caseId, String text) {
        return caseManager.addNote(caseId, text);
    }

    // F07: IOC extraction and threat-intel enrichment

    /**
     * Extracts the case's indicators, looks them up with the configured providers and saves
     * them on the case. Provider failures (missing key, timeout, rate limit) only mark the
     * affected indicators as unavailable. An empty list means no indicators were found.
     */
    public List<Ioc> enrichIocs(String caseId) {
        Case c = caseManager.getCase(caseId);
        List<Ioc> iocs = enrichment.enrich(c);
        caseManager.recordIocs(c.getId(), iocs);
        return iocs;
    }

    /** Names of the threat-intel services that have an API key (empty if none). */
    public List<String> threatIntelProviders() {
        return enrichment.providerNames();
    }

    // F08: MITRE ATT&CK mapping

    /**
     * Maps the case to ATT&CK techniques and saves them. The detections' technique IDs are
     * resolved in the bundled catalogue; the agent is asked when there are none, or when
     * {@code askAgent} is true. Suggested IDs that are not in the catalogue are dropped.
     *
     * @throws IllegalStateException "No mapping available" if the case has no IDs and the agent could not answer
     */
    public MappingResult mapAttack(String caseId, boolean askAgent) {
        Case c = caseManager.getCase(caseId);
        MappingResult r = attackMapper.map(c, askAgent, cs -> agent().suggestTechniques(cs));
        caseManager.recordTechniques(c.getId(), r.techniques());
        return r;
    }

    // F06: AI case triage

    /**
     * Lets the agent investigate the case and stores its verdict; a NEW case moves to
     * INVESTIGATING. If the AI service fails, the case is left unchanged.
     *
     * @throws IllegalStateException if the case is closed, or no API key is configured
     * @throws LlmException          if the AI service cannot be reached
     */
    public TriageVerdict triageCase(String caseId) {
        Case c = caseManager.getCase(caseId);
        if (c.isClosed()) {
            throw new IllegalStateException(c.getId() + " is closed; reopen it before running AI triage");
        }
        TriageVerdict v = agent().triage(c);
        caseManager.recordVerdict(c.getId(), v);
        return v;
    }

    // F04: AI log summary

    /** @throws IllegalArgumentException if no file with that batch ID was imported (no model call is made) */
    public AgentResult summarizeLog(String batchId) {
        List<SecurityEvent> batch = eventStore.getBatch(batchId);
        if (batch.isEmpty()) {
            throw new IllegalArgumentException("No imported file named '" + batchId + "'. Imported files: "
                    + (listBatches().isEmpty() ? "none" : String.join(", ", listBatches())));
        }
        return agent().summarize(batchId, batch.size(), timeRange(batch));
    }

    // F12: ask the agent

    /** @throws IllegalStateException if nothing has been imported yet (no model call is made) */
    public AgentResult ask(String question) {
        if (question == null || question.isBlank()) {
            throw new IllegalArgumentException("Type a question");
        }
        if (eventStore.size() == 0) {
            throw new IllegalStateException("Import a file first");
        }
        List<String> files = new ArrayList<>();
        for (String b : listBatches()) {
            files.add(b + " (" + eventStore.getBatch(b).size() + " events)");
        }
        String context = eventStore.size() + " events in " + String.join(", ", files) + ", " + timeRange(eventStore.all());
        return agent().answer(question.strip(), context);
    }

    /** Which model the AI features use, for example "openai-compatible gpt-4o-mini at api.openai.com". */
    public String describeModel() {
        return agent().describeModel();
    }

    /** Tokens used by the most recent AI request. */
    public TokenUsage getLastUsage() {
        return agent == null ? TokenUsage.NONE : agent.getLastUsage();
    }

    private synchronized SocAgent agent() {
        if (agent == null) {
            agent = agentFactory.get();
        }
        return agent;
    }

    private static String timeRange(List<SecurityEvent> events) {
        Instant first = events.stream().map(SecurityEvent::timestamp).min(Comparator.naturalOrder()).orElseThrow();
        Instant last = events.stream().map(SecurityEvent::timestamp).max(Comparator.naturalOrder()).orElseThrow();
        return "from " + first + " to " + last;
    }

    // F13: dashboard

    public DashboardStats getDashboardStats() {
        return new DashboardStats(eventStore.size(),
                top(eventStore.countBy("srcIp", null)),
                top(eventStore.countBy("user", null)),
                caseManager.countByState());
    }

    private static Map<String, Integer> top(Map<String, Integer> sortedCounts) {
        Map<String, Integer> top = new LinkedHashMap<>();
        for (Map.Entry<String, Integer> e : sortedCounts.entrySet()) {
            if (top.size() == TOP_N) {
                break;
            }
            top.put(e.getKey(), e.getValue());
        }
        return top;
    }
}
