package ca.yorku.triagedesk.cli;

import ca.yorku.triagedesk.agent.TokenUsage;
import ca.yorku.triagedesk.attack.MappingResult;
import ca.yorku.triagedesk.config.AppConfig;
import ca.yorku.triagedesk.domain.AgentResult;
import ca.yorku.triagedesk.domain.AttackTechnique;
import ca.yorku.triagedesk.domain.Case;
import ca.yorku.triagedesk.domain.DashboardStats;
import ca.yorku.triagedesk.domain.Finding;
import ca.yorku.triagedesk.domain.Ioc;
import ca.yorku.triagedesk.domain.ResponsePlan;
import ca.yorku.triagedesk.domain.TriageVerdict;
import ca.yorku.triagedesk.facade.DetectionResult;
import ca.yorku.triagedesk.facade.ImportResult;
import ca.yorku.triagedesk.facade.ReportResult;
import ca.yorku.triagedesk.facade.SocAssistant;
import java.io.PrintWriter;
import java.nio.file.Path;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.function.Supplier;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;
import picocli.CommandLine.Spec;

/**
 * Command-line interface. Like the GUI controllers, every command only calls the
 * SocAssistant facade and prints the result. Each run is a new process, so the
 * facade loads the events and cases saved in the data folder.
 */
@Command(name = "triagedesk", mixinStandardHelpOptions = true, version = "TriageDesk 0.1.0",
        description = "AI assistant for SOC alert triage and log analysis.")
public class TriageDeskCli implements Runnable {

    private static final int TITLE_WIDTH = 80;

    @Spec
    CommandSpec spec;

    @Option(names = {"-d", "--data-dir"}, paramLabel = "DIR",
            description = "Folder for imported events and cases (default: TRIAGEDESK_DATA_DIR or ./data).")
    Path dataDir;

    private final Supplier<AppConfig> configSupplier;
    private SocAssistant assistant;

    public TriageDeskCli() {
        this(AppConfig::load);
    }

    public TriageDeskCli(Supplier<AppConfig> configSupplier) {
        this.configSupplier = configSupplier;
    }

    public static void main(String[] args) {
        System.exit(commandLine(new TriageDeskCli()).execute(args));
    }

    /** Builds the picocli command line; errors are printed as one "Error: ..." line with exit code 1. */
    public static CommandLine commandLine(TriageDeskCli cli) {
        CommandLine cl = new CommandLine(cli);
        cl.setExecutionExceptionHandler((ex, commandLine, parseResult) -> {
            commandLine.getErr().println("Error: " + (ex.getMessage() != null ? ex.getMessage() : ex.toString()));
            return 1;
        });
        return cl;
    }

    @Override
    public void run() {
        spec.commandLine().usage(out());
    }

    // F01, F02

    @Command(name = "import", description = "Import Wazuh alerts.json, Linux auth.log or Apache/Nginx access-log files.")
    int importFile(@Parameters(paramLabel = "FILE", arity = "1..*", description = "Files to import.") List<Path> files) {
        int exitCode = 0;
        for (Path file : files) {
            try {
                ImportResult r = assistant().importFile(file);
                out().printf("Imported %d events from %s (%s format), skipped %d unreadable lines%n",
                        r.imported(), r.batchId(), r.format(), r.skipped());
            } catch (IllegalArgumentException e) {
                err().println("Error: " + e.getMessage());
                exitCode = 1;
            }
        }
        return exitCode;
    }

    // F03, F05

    @Command(name = "detect", description = "Run the detection rules and group the findings into prioritised cases.")
    int detect() {
        DetectionResult r = assistant().runDetections();
        r.warnings().forEach(w -> err().println("Warning: " + w));
        if (r.findings() == 0) {
            out().println("No suspicious activity found.");
            return 0;
        }
        out().printf("Detectors found %d findings.%n", r.findings());
        if (r.cases().isEmpty()) {
            out().println("No new cases: every finding is already part of an existing case.");
        } else {
            out().printf("%d case(s) created or updated:%n", r.cases().size());
            printCaseTable(r.cases());
        }
        return 0;
    }

    @Command(name = "cases", description = "List all cases, highest priority first.")
    int cases() {
        List<Case> cases = assistant().listCases();
        if (cases.isEmpty()) {
            out().println("No cases yet. Import files, then run: triagedesk detect");
        } else {
            printCaseTable(cases);
        }
        return 0;
    }

    @Command(name = "show", description = "Show the details of one case.")
    int show(@Parameters(paramLabel = "CASE_ID") String caseId) {
        Case c = assistant().getCase(caseId);
        PrintWriter out = out();
        out.printf("%s  [%s]  %s  priority %d%n", c.getId(), c.getState().name(), c.getSeverity(), c.getPriority());
        out.println("Title:   " + c.getTitle());
        out.println("Created: " + c.getCreatedAt());
        if (c.getResolution() != null) {
            out.println("Closed as: " + c.getResolution());
        }
        out.printf("%nFindings (%d):%n", c.getFindings().size());
        Set<String> techniqueIds = new LinkedHashSet<>();
        for (Finding f : c.getFindings()) {
            int n = f.events().size();
            out.printf("  - [%s] %s %s .. %s, %d %s%n      %s%n", f.detector(), f.severity(),
                    f.firstSeen(), f.lastSeen(), n, n == 1 ? "event" : "events", f.title());
            techniqueIds.addAll(f.techniqueIds());
        }
        out.println();
        out.println("ATT&CK technique IDs from detections: " + (techniqueIds.isEmpty() ? "none" : String.join(", ", techniqueIds)));
        if (!c.getTechniques().isEmpty()) {
            out.println("ATT&CK techniques:");
            c.getTechniques().forEach(t -> out.printf("  %-10s %s (%s)%n", t.id(), t.name(), t.tactic()));
        }
        if (!c.getIocs().isEmpty()) {
            out.println("Indicators:");
            printIocs(out, c.getIocs());
        }
        out.println("AI verdict: " + (c.getVerdict() == null ? "not triaged yet"
                : String.format(Locale.ROOT, "%s (confidence %.2f)", c.getVerdict().verdict(), c.getVerdict().confidence())));
        if (c.getResponsePlan() != null) {
            out.println("Response plan:");
            printPlan(out, c.getResponsePlan());
        }
        out.println("Allowed actions: " + String.join(", ", c.getState().allowedActions()));
        printList(out, "Notes", c.getNotes());
        printList(out, "History", c.getHistory());
        return 0;
    }

    // F09

    @Command(name = "status", description = "Change a case's status: start, escalate, close or reopen.")
    int status(@Parameters(index = "0", paramLabel = "CASE_ID") String caseId,
               @Parameters(index = "1", paramLabel = "ACTION", description = "start, escalate, close or reopen") String action,
               @Option(names = {"-m", "--comment"}, paramLabel = "TEXT",
                       description = "Reason (escalate) or comment (close).") String comment,
               @Option(names = "--as", paramLabel = "RESOLUTION",
                       description = "For close: true_positive, false_positive or benign.") String resolution) {
        Case c = assistant().changeStatus(caseId, action, resolution, comment);
        out().printf("%s is now %s.%n", c.getId(), c.getState().name());
        return 0;
    }

    @Command(name = "note", description = "Add a timestamped note to a case.")
    int note(@Parameters(index = "0", paramLabel = "CASE_ID") String caseId,
             @Parameters(index = "1..*", arity = "1..*", paramLabel = "TEXT") List<String> words) {
        Case c = assistant().addNote(caseId, String.join(" ", words));
        out().printf("Note added to %s (%d notes).%n", c.getId(), c.getNotes().size());
        return 0;
    }

    // F07

    @Command(name = "enrich", description = "Extract a case's IPs, URLs, domains and hashes and look up their reputation.")
    int enrich(@Parameters(paramLabel = "CASE_ID") String caseId) {
        List<String> providers = assistant().threatIntelProviders();
        out().println(providers.isEmpty()
                ? "No threat-intel provider configured (set ABUSEIPDB_API_KEY or VIRUSTOTAL_API_KEY in .env);"
                        + " indicators are listed without scores."
                : "Looking up indicators with " + String.join(", ", providers) + " ...");
        List<Ioc> iocs = assistant().enrichIocs(caseId);
        if (iocs.isEmpty()) {
            out().println("No indicators found.");
            return 0;
        }
        printIocs(out(), iocs);
        return 0;
    }

    // F08

    @Command(name = "map", description = "Map a case to MITRE ATT&CK techniques (detections first, the AI agent if needed).")
    int map(@Parameters(paramLabel = "CASE_ID") String caseId,
            @Option(names = "--ai", description = "Also ask the AI agent for techniques the detections did not tag.")
            boolean askAgent) {
        MappingResult r = assistant().mapAttack(caseId, askAgent);
        PrintWriter out = out();
        if (r.techniques().isEmpty()) {
            out.println("No ATT&CK techniques could be mapped.");
        } else {
            out.printf("  %-10s %-9s %-40s %s%n", "ID", "SOURCE", "TECHNIQUE", "TACTICS");
            for (AttackTechnique t : r.techniques()) {
                out.printf("  %-10s %-9s %-40s %s%n", t.id(), r.sourceOf(t.id()), t.name(), t.tactic());
            }
        }
        if (!r.rejected().isEmpty()) {
            out.println("Not in the ATT&CK catalogue, ignored: " + String.join(", ", r.rejected()));
        }
        printUsage(out);
        return 0;
    }

    // F10

    @Command(name = "respond", description = "Let the AI agent recommend response steps for a triaged case.")
    int respond(@Parameters(paramLabel = "CASE_ID") String caseId) {
        String id = caseId.strip().toUpperCase(Locale.ROOT);
        ResponsePlan plan = assistant().recommendResponse(caseId);
        out().printf("Response plan for %s:%n", id);
        printPlan(out(), plan);
        out().println("Tick off a step with: triagedesk done " + id + " STEP_NUMBER");
        printUsage(out());
        return 0;
    }

    @Command(name = "done", description = "Mark a response step as done.")
    int done(@Parameters(index = "0", paramLabel = "CASE_ID") String caseId,
             @Parameters(index = "1", paramLabel = "STEP_NUMBER") int step) {
        Case c = assistant().markStepDone(caseId, step);
        printPlan(out(), c.getResponsePlan());
        return 0;
    }

    // F11

    @Command(name = "report", description = "Write a Markdown incident report for a case.")
    int report(@Parameters(paramLabel = "CASE_ID") String caseId,
               @Option(names = {"-o", "--output"}, paramLabel = "FILE",
                       description = "Report file (default: reports/CASE_ID.md).") Path output) {
        ReportResult r = assistant().generateReport(caseId, output);
        if (r.warning() != null) {
            err().println("Warning: " + r.warning() + " (the report was written without it)");
        }
        out().println("Report written to " + r.path().toAbsolutePath().normalize());
        printUsage(out());
        return 0;
    }

    // F06

    @Command(name = "triage", description = "Let the AI agent investigate a case and propose a verdict.")
    int triage(@Parameters(paramLabel = "CASE_ID") String caseId) {
        out().println("Investigating " + caseId.strip().toUpperCase(Locale.ROOT) + " with " + assistant().describeModel() + " ...");
        TriageVerdict v = assistant().triageCase(caseId);
        Case c = assistant().getCase(caseId);
        PrintWriter out = out();
        out.printf(Locale.ROOT, "%nVerdict:    %s (confidence %.2f)%n", v.verdict(), v.confidence());
        out.println("Reasoning:  " + v.reasoning());
        printTrace(out, v.toolTrace());
        out.printf("%nCase %s is now %s.%n", c.getId(), c.getState().name());
        printUsage(out);
        return 0;
    }

    // F04

    @Command(name = "summarize", description = "Let the AI agent summarise one imported file (see 'stats' for file names).")
    int summarize(@Parameters(paramLabel = "FILE_NAME", description = "Imported file name, for example auth.log") String batchId) {
        out().println("Summarising " + batchId + " with " + assistant().describeModel() + " ...");
        printAgentResult(assistant().summarizeLog(batchId));
        return 0;
    }

    // F12

    @Command(name = "ask", description = "Ask the AI agent a question about the imported data.")
    int ask(@Parameters(paramLabel = "QUESTION", arity = "1..*") List<String> words) {
        out().println("Asking " + assistant().describeModel() + " ...");
        printAgentResult(assistant().ask(String.join(" ", words)));
        return 0;
    }

    // F13

    @Command(name = "stats", description = "Show totals for the imported events and the case queue.")
    int stats() {
        DashboardStats s = assistant().getDashboardStats();
        PrintWriter out = out();
        if (s.isEmpty()) {
            out.println("No data. Import a file to begin.");
            return 0;
        }
        out.println("Total events:   " + s.totalEvents());
        out.println("Imported files: " + String.join(", ", assistant().listBatches()));
        printCounts(out, "Top source IPs", s.topSourceIps());
        printCounts(out, "Top users", s.topUsers());
        printCounts(out, "Cases by state", s.casesByState());
        return 0;
    }

    private SocAssistant assistant() {
        if (assistant == null) {
            AppConfig config = configSupplier.get();
            assistant = dataDir != null ? SocAssistant.create(config, dataDir) : SocAssistant.create(config);
        }
        return assistant;
    }

    private void printCaseTable(List<Case> cases) {
        PrintWriter out = out();
        out.printf("%-10s %-13s %-8s %3s %4s  %s%n", "ID", "STATE", "SEVERITY", "PRI", "FIND", "TITLE");
        for (Case c : cases) {
            String title = c.getTitle().length() > TITLE_WIDTH
                    ? c.getTitle().substring(0, TITLE_WIDTH - 3) + "..." : c.getTitle();
            out.printf("%-10s %-13s %-8s %3d %4d  %s%n", c.getId(), c.getState().name(), c.getSeverity(),
                    c.getPriority(), c.getFindings().size(), title);
        }
    }

    private static void printPlan(PrintWriter out, ResponsePlan plan) {
        for (int i = 0; i < plan.getSteps().size(); i++) {
            out.printf("  %d. [%s] %s%n", i + 1, plan.isDone(i) ? "x" : " ", plan.getSteps().get(i));
        }
    }

    private static void printIocs(PrintWriter out, List<Ioc> iocs) {
        out.printf("  %-6s %5s  %-40s %s%n", "TYPE", "SCORE", "VALUE", "SOURCE");
        for (Ioc i : iocs) {
            String value = i.value().length() > 40 ? i.value().substring(0, 37) + "..." : i.value();
            out.printf("  %-6s %5s  %-40s %s%n", i.type(), i.isScored() ? String.valueOf(i.score()) : "n/a", value,
                    i.source() == null ? "" : i.source());
        }
    }

    private void printAgentResult(AgentResult r) {
        PrintWriter out = out();
        out.println();
        out.println(r.text());
        if (r.stoppedEarly()) {
            out.println("[Incomplete: the step limit was reached before the agent finished.]");
        }
        printTrace(out, r.toolTrace());
        printUsage(out);
    }

    private static void printTrace(PrintWriter out, List<String> trace) {
        out.printf("%nTool calls (%d):%n", trace.size());
        for (int i = 0; i < trace.size(); i++) {
            out.printf("  %d. %s%n", i + 1, trace.get(i));
        }
    }

    private void printUsage(PrintWriter out) {
        TokenUsage u = assistant().getLastUsage();
        if (u.modelCalls() > 0) {
            out.printf("Model calls: %d, tokens: %d in, %d out%n", u.modelCalls(), u.promptTokens(), u.completionTokens());
        }
    }

    private static void printList(PrintWriter out, String heading, List<String> items) {
        out.printf("%n%s (%d):%n", heading, items.size());
        items.forEach(i -> out.println("  " + i));
    }

    private static void printCounts(PrintWriter out, String heading, Map<String, Integer> counts) {
        out.printf("%n%s:%n", heading);
        if (counts.isEmpty()) {
            out.println("  (none)");
        }
        counts.forEach((k, v) -> out.printf("  %-20s %6d%n", k, v));
    }

    private PrintWriter out() {
        return spec.commandLine().getOut();
    }

    private PrintWriter err() {
        return spec.commandLine().getErr();
    }
}
