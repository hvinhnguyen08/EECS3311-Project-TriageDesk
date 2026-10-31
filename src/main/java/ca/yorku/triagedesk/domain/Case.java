package ca.yorku.triagedesk.domain;

import java.time.Clock;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;

/**
 * A group of related findings that the analyst investigates as one unit. Everything the
 * analyst or the agent adds to the case (IOCs, techniques, verdict, plan, notes) is
 * recorded in its history.
 */
public class Case {

    private final String id;
    private final String title;
    private final Clock clock;
    private final Instant createdAt;
    private Severity severity;
    private int priority;
    private final List<Finding> findings = new ArrayList<>();
    private List<Ioc> iocs = List.of();
    private List<AttackTechnique> techniques = List.of();
    private TriageVerdict verdict;
    private ResponsePlan responsePlan;
    private final List<String> notes = new ArrayList<>();
    private final List<String> history = new ArrayList<>();

    public Case(String id, String title, List<Finding> findings) {
        this(id, title, findings, Clock.systemUTC());
    }

    public Case(String id, String title, List<Finding> findings, Clock clock) {
        this.id = Objects.requireNonNull(id, "id");
        this.title = Objects.requireNonNull(title, "title");
        this.clock = Objects.requireNonNull(clock, "clock");
        if (findings == null || findings.isEmpty()) {
            throw new IllegalArgumentException("A case needs at least one finding");
        }
        this.createdAt = now();
        this.severity = Severity.LOW;
        for (Finding f : findings) {
            this.findings.add(f);
            this.severity = Severity.max(this.severity, f.severity());
        }
        recordHistory("Case created from " + findings.size() + " finding(s)");
    }

    /** Adds a related finding to an existing case; the case severity becomes the highest of its findings. */
    public void addFinding(Finding f) {
        findings.add(Objects.requireNonNull(f, "finding"));
        severity = Severity.max(severity, f.severity());
        recordHistory("Finding added: " + f.title());
    }

    public void addNote(String text) {
        if (text == null || text.isBlank()) {
            throw new IllegalArgumentException("A note cannot be empty");
        }
        notes.add(timestamp() + " " + text.strip());
        recordHistory("Note added");
    }

    public void setIocs(List<Ioc> iocs) {
        this.iocs = iocs == null ? List.of() : List.copyOf(iocs);
        recordHistory("IOCs updated (" + this.iocs.size() + ")");
    }

    public void setTechniques(List<AttackTechnique> techniques) {
        this.techniques = techniques == null ? List.of() : List.copyOf(techniques);
        recordHistory("ATT&CK techniques updated (" + this.techniques.size() + ")");
    }

    public void setVerdict(TriageVerdict v) {
        this.verdict = Objects.requireNonNull(v, "verdict");
        recordHistory(String.format(Locale.ROOT, "AI verdict: %s (confidence %.2f)", v.verdict(), v.confidence()));
    }

    public void setResponsePlan(ResponsePlan p) {
        this.responsePlan = Objects.requireNonNull(p, "responsePlan");
        recordHistory("Response plan set (" + p.getSteps().size() + " steps)");
    }

    public void setPriority(int priority) {
        this.priority = priority;
    }

    /** All evidence events of all findings, without duplicates, oldest first. */
    public List<SecurityEvent> getEvents() {
        Map<String, SecurityEvent> byId = new LinkedHashMap<>();
        for (Finding f : findings) {
            for (SecurityEvent e : f.events()) {
                byId.putIfAbsent(e.id(), e);
            }
        }
        List<SecurityEvent> events = new ArrayList<>(byId.values());
        events.sort(Comparator.comparing(SecurityEvent::timestamp));
        return events;
    }

    /** Appends a timestamped entry to the case history. */
    public void recordHistory(String entry) {
        history.add(timestamp() + " " + entry);
    }

    private Instant now() {
        return clock.instant().truncatedTo(ChronoUnit.SECONDS);
    }

    private String timestamp() {
        return "[" + now() + "]";
    }

    public String getId() { return id; }
    public String getTitle() { return title; }
    public Instant getCreatedAt() { return createdAt; }
    public Severity getSeverity() { return severity; }
    public int getPriority() { return priority; }
    public List<Finding> getFindings() { return Collections.unmodifiableList(findings); }
    public List<Ioc> getIocs() { return iocs; }
    public List<AttackTechnique> getTechniques() { return techniques; }
    public TriageVerdict getVerdict() { return verdict; }
    public ResponsePlan getResponsePlan() { return responsePlan; }
    public List<String> getNotes() { return Collections.unmodifiableList(notes); }
    public List<String> getHistory() { return Collections.unmodifiableList(history); }
}
