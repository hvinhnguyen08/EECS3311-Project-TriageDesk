package ca.yorku.triagedesk.cli;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ca.yorku.triagedesk.config.AppConfig;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import picocli.CommandLine;

class TriageDeskCliTest {

    @TempDir
    Path dataDir;

    /** Output of one CLI run. Each run uses a new TriageDeskCli, like a new process. */
    private record Run(int exitCode, String out, String err) {
    }

    private Run run(String... args) {
        StringWriter out = new StringWriter();
        StringWriter err = new StringWriter();
        CommandLine cl = TriageDeskCli.commandLine(new TriageDeskCli(() -> AppConfig.load(null, Map.of())));
        cl.setOut(new PrintWriter(out, true));
        cl.setErr(new PrintWriter(err, true));
        List<String> all = new ArrayList<>(List.of("--data-dir", dataDir.toString()));
        all.addAll(List.of(args));
        int code = cl.execute(all.toArray(String[]::new));
        return new Run(code, out.toString(), err.toString());
    }

    @Test
    void importDetectAndListCases() {
        Run imported = run("import", "samples/alerts.json", "samples/auth.log", "samples/access.log");
        assertEquals(0, imported.exitCode(), imported.err());
        assertTrue(imported.out().contains("Imported 12 events from alerts.json (wazuh format), skipped 0 unreadable lines"));
        assertTrue(imported.out().contains("Imported 51 events from access.log (apache format)"));

        Run detected = run("detect");
        assertEquals(0, detected.exitCode(), detected.err());
        assertTrue(detected.out().contains("Detectors found 8 findings."));
        assertTrue(detected.out().contains("3 case(s) created or updated:"));
        assertTrue(detected.out().contains("CASE-0001  NEW           HIGH      80    4"), detected.out());

        Run again = run("detect");
        assertTrue(again.out().contains("No new cases"));

        Run cases = run("cases");
        assertEquals(4, cases.out().lines().count(), cases.out());
    }

    @Test
    void caseLifecycleFromTheCommandLine() {
        run("import", "samples/auth.log");
        run("detect");

        Run refused = run("status", "CASE-0001", "escalate", "-m", "too early");
        assertEquals(1, refused.exitCode());
        assertEquals("Error: Cannot escalate a case that is NEW. Allowed: start, close", refused.err().strip());

        assertEquals("CASE-0001 is now INVESTIGATING.", run("status", "CASE-0001", "start").out().strip());
        assertEquals(0, run("note", "CASE-0001", "Called", "the", "server", "owner").exitCode());
        Run closed = run("status", "CASE-0001", "close", "--as", "true_positive", "-m", "Password reset");
        assertEquals("CASE-0001 is now CLOSED.", closed.out().strip());

        Run shown = run("show", "case-0001");
        assertTrue(shown.out().contains("CASE-0001  [CLOSED]"), shown.out());
        assertTrue(shown.out().contains("Closed as: TRUE_POSITIVE"));
        assertTrue(shown.out().contains("Called the server owner"));
        assertTrue(shown.out().contains("Allowed actions: reopen"));
    }

    @Test
    void errorsAreOneLineWithExitCodeOne() {
        Run noData = run("detect");
        assertEquals(1, noData.exitCode());
        assertEquals("Error: Import a file first", noData.err().strip());

        Run unsupported = run("import", "samples/errors/unsupported-format.txt", "samples/auth.log");
        assertEquals(1, unsupported.exitCode());
        assertTrue(unsupported.err().contains("Unsupported file format"));
        assertTrue(unsupported.out().contains("Imported 35 events from auth.log"), "other files still import");

        Run missing = run("import", "samples/nope.log");
        assertEquals("Error: File not found: " + Path.of("samples/nope.log"), missing.err().strip());

        Run unknownCase = run("show", "CASE-0042");
        assertEquals("Error: No case with ID CASE-0042", unknownCase.err().strip());

        Run badCommand = run("explode");
        assertEquals(2, badCommand.exitCode(), "picocli usage error");
    }

    @Test
    void aiCommandsRunOfflineWithTheMockProvider() {
        run("import", "samples/auth.log");
        run("detect");

        Run triage = run("triage", "case-0001");
        assertEquals(0, triage.exitCode(), triage.err());
        assertTrue(triage.out().contains("Investigating CASE-0001 with mock (offline, scripted replies)"));
        assertTrue(triage.out().contains("Verdict:    NEEDS_REVIEW (confidence 0.00)"), triage.out());
        assertTrue(triage.out().contains("Tool calls (1):"));
        assertTrue(triage.out().contains("Case CASE-0001 is now INVESTIGATING."));
        assertTrue(run("show", "CASE-0001").out().contains("AI verdict: NEEDS_REVIEW"));

        Run summary = run("summarize", "auth.log");
        assertEquals(0, summary.exitCode(), summary.err());
        assertTrue(summary.out().contains("Offline mode"));

        Run ask = run("ask", "Which", "IP", "failed", "most?");
        assertEquals(0, ask.exitCode(), ask.err());
        assertTrue(ask.out().contains("203.0.113.7"));

        Run unknownFile = run("summarize", "nope.log");
        assertEquals("Error: No imported file named 'nope.log'. Imported files: auth.log", unknownFile.err().strip());
    }

    @Test
    void enrichWithoutThreatIntelKeys() {
        run("import", "samples/alerts.json", "samples/auth.log", "samples/access.log");
        run("detect");

        Run enrich = run("enrich", "CASE-0002");
        assertEquals(0, enrich.exitCode(), enrich.err());
        assertTrue(enrich.out().startsWith("No threat-intel provider configured"), enrich.out());
        assertTrue(enrich.out().contains("ip       n/a  198.51.100.23"), enrich.out());
        assertTrue(enrich.out().contains("domain   n/a  sqlmap.org"));
        assertTrue(run("show", "CASE-0002").out().contains("Indicators:"));
        assertTrue(run("enrich", "CASE-0003").out().contains("No indicators found."));
    }

    @Test
    void mapFromTheCommandLine() {
        run("import", "samples/alerts.json", "samples/access.log");
        run("detect");

        Run map = run("map", "CASE-0002");
        assertEquals(0, map.exitCode(), map.err());
        assertTrue(map.out().contains("T1595.002  detection Vulnerability Scanning"), map.out());
        assertTrue(map.out().matches("(?s).*T1190 +detection Exploit Public-Facing Application +Initial Access.*"), map.out());

        Run offline = run("map", "CASE-0002", "--ai");
        assertEquals(0, offline.exitCode(), offline.err());
        assertTrue(run("show", "CASE-0002").out().contains("ATT&CK techniques:"));
    }

    @Test
    void respondDoneAndReportOffline() throws Exception {
        run("import", "samples/auth.log");
        run("detect");
        assertTrue(run("respond", "CASE-0001").err().contains("Run AI Triage first"));

        run("triage", "CASE-0001");
        Run respond = run("respond", "CASE-0001");
        assertEquals(0, respond.exitCode(), respond.err());
        assertTrue(respond.out().contains("1. [ ] Offline mode"), respond.out());
        assertTrue(run("done", "CASE-0001", "1").out().contains("1. [x] Offline mode"));
        assertEquals(1, run("done", "CASE-0001", "5").exitCode());

        Path file = dataDir.resolve("out/report.md");
        Run report = run("report", "CASE-0001", "-o", file.toString());
        assertEquals(0, report.exitCode(), report.err());
        assertTrue(report.out().contains("Report written to"));
        assertTrue(java.nio.file.Files.readString(file).contains("# Incident report: CASE-0001"));
    }

    @Test
    void statsWithAndWithoutData() {
        assertTrue(run("stats").out().contains("No data. Import a file to begin."));

        run("import", "samples/auth.log");
        Run stats = run("stats");

        assertTrue(stats.out().contains("Total events:   35"), stats.out());
        assertTrue(stats.out().contains("203.0.113.7"));
        assertTrue(stats.out().contains("Cases by state:"));
    }
}
