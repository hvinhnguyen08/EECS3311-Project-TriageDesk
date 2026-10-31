package ca.yorku.triagedesk.facade;

import ca.yorku.triagedesk.casemgmt.CaseManager;
import ca.yorku.triagedesk.config.AppConfig;
import ca.yorku.triagedesk.detect.DetectionEngine;
import ca.yorku.triagedesk.domain.Case;
import ca.yorku.triagedesk.domain.DashboardStats;
import ca.yorku.triagedesk.domain.Finding;
import ca.yorku.triagedesk.domain.SecurityEvent;
import ca.yorku.triagedesk.ingest.EventStore;
import ca.yorku.triagedesk.ingest.LogParser;
import ca.yorku.triagedesk.ingest.LogParserFactory;
import ca.yorku.triagedesk.ingest.UnsupportedFormatException;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

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

    public SocAssistant(EventStore eventStore, LogParserFactory parserFactory,
                        DetectionEngine detectionEngine, CaseManager caseManager) {
        this.eventStore = eventStore;
        this.parserFactory = parserFactory;
        this.detectionEngine = detectionEngine;
        this.caseManager = caseManager;
    }

    /** Builds the standard subsystems from the configuration and loads the saved events and cases. */
    public static SocAssistant create(AppConfig config) {
        return create(config, config.getDataDir());
    }

    /** Same as {@link #create(AppConfig)} but with an explicit data folder (CLI --data-dir option). */
    public static SocAssistant create(AppConfig config, Path dataDir) {
        EventStore store = new EventStore(dataDir);
        store.load();
        CaseManager cases = new CaseManager(dataDir);
        cases.load();
        return new SocAssistant(store, new LogParserFactory(config.getLogTimeZone()),
                DetectionEngine.withStandardDetectors(config), cases);
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
