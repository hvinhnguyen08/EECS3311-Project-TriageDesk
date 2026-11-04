package ca.yorku.triagedesk.casemgmt;

import ca.yorku.triagedesk.domain.Case;
import ca.yorku.triagedesk.domain.Finding;
import ca.yorku.triagedesk.domain.Ioc;
import ca.yorku.triagedesk.domain.SecurityEvent;
import ca.yorku.triagedesk.domain.TriageVerdict;
import ca.yorku.triagedesk.util.Json;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Turns findings into a prioritised case queue and keeps the cases, one JSON file per
 * case in {@code <dataDir>/cases/}. Related findings (same source IP, or same host when a
 * finding has no IP, within 60 minutes) share a case.
 */
public class CaseManager {

    static final Duration GROUP_WINDOW = Duration.ofMinutes(60);
    private static final Pattern ID_PATTERN = Pattern.compile("CASE-(\\d+)");

    private final Map<String, Case> cases = new LinkedHashMap<>();
    private final Path casesDir;
    private final Clock clock;
    private final ObjectMapper mapper = Json.mapper();
    private final List<String> warnings = new ArrayList<>();
    private int lastNumber;

    public CaseManager(Path dataDir) {
        this(dataDir, Clock.systemUTC());
    }

    public CaseManager(Path dataDir, Clock clock) {
        this.casesDir = dataDir.resolve("cases");
        this.clock = clock;
    }

    /** Replaces the in-memory cases with the saved ones. Unreadable files are skipped with a warning. */
    public synchronized void load() {
        cases.clear();
        warnings.clear();
        lastNumber = 0;
        if (!Files.isDirectory(casesDir)) {
            return;
        }
        List<Case> loaded = new ArrayList<>();
        try (DirectoryStream<Path> files = Files.newDirectoryStream(casesDir, "*.json")) {
            for (Path file : files) {
                try {
                    loaded.add(Case.fromSnapshot(mapper.readValue(file.toFile(), Case.Snapshot.class), clock));
                } catch (IOException | RuntimeException e) {
                    warnings.add("Could not read " + file.getFileName() + ": " + e.getMessage());
                }
            }
        } catch (IOException e) {
            throw new UncheckedIOException("Could not read " + casesDir, e);
        }
        loaded.sort(Comparator.comparing(Case::getId));
        for (Case c : loaded) {
            cases.put(c.getId(), c);
            lastNumber = Math.max(lastNumber, number(c.getId()));
        }
    }

    /**
     * Adds findings to the case queue. A finding already recorded in a case is ignored (so
     * running detections twice changes nothing); a finding related to an existing case is
     * added to it; the rest are grouped into new cases.
     *
     * @return the cases created or updated, highest priority first
     */
    public synchronized List<Case> createCases(List<Finding> findings) {
        warnings.clear();
        List<Finding> sorted = new ArrayList<>(findings);
        sorted.sort(Comparator.comparing(Finding::firstSeen));

        Set<Case> affected = new LinkedHashSet<>();
        List<Finding> unmatched = new ArrayList<>();
        for (Finding f : sorted) {
            if (isRecorded(f)) {
                continue;
            }
            Case existing = findRelatedCase(f);
            if (existing != null) {
                existing.addFinding(f);
                affected.add(existing);
            } else {
                unmatched.add(f);
            }
        }

        for (List<Finding> group : groupFindings(unmatched)) {
            Case c = new Case(nextId(), titleFor(group), group, clock);
            cases.put(c.getId(), c);
            affected.add(c);
        }

        for (Case c : affected) {
            c.setPriority(computePriority(c));
            save(c);
        }
        return sortByPriority(new ArrayList<>(affected));
    }

    public synchronized Case getCase(String caseId) {
        Case c = caseId == null ? null : cases.get(caseId.strip().toUpperCase(Locale.ROOT));
        if (c == null) {
            throw new IllegalArgumentException("No case with ID " + caseId);
        }
        return c;
    }

    /** Applies start, escalate or reopen (see {@link CaseActions}); the comment is the escalation reason. */
    public synchronized Case applyAction(String caseId, String action, String comment) {
        return applyAction(caseId, action, null, comment);
    }

    /**
     * Applies a lifecycle action and saves the case. For "close", {@code resolution} is
     * true_positive, false_positive or benign and a comment is required.
     *
     * @throws InvalidTransitionException if the current state does not allow the action (case unchanged)
     * @throws IllegalArgumentException   for an unknown case or action, or missing input (case unchanged)
     */
    public synchronized Case applyAction(String caseId, String action, String resolution, String comment) {
        Case c = getCase(caseId);
        String a = action == null ? "" : action.strip().toLowerCase(Locale.ROOT);
        switch (a) {
            case CaseActions.START -> c.startInvestigation();
            case CaseActions.ESCALATE -> c.escalate(comment);
            case CaseActions.CLOSE -> c.close(resolution, comment);
            case CaseActions.REOPEN -> c.reopen();
            default -> throw new IllegalArgumentException(
                    "Unknown action '" + action + "'. Use one of: " + String.join(", ", CaseActions.ALL));
        }
        warnings.clear();
        save(c);
        return c;
    }

    /** Adds a timestamped note and saves the case; an empty note is rejected. */
    public synchronized Case addNote(String caseId, String text) {
        Case c = getCase(caseId);
        c.addNote(text);
        warnings.clear();
        save(c);
        return c;
    }

    /** Stores the AI verdict; a NEW case moves to INVESTIGATING (someone is now looking at it). */
    public synchronized Case recordVerdict(String caseId, TriageVerdict v) {
        Case c = getCase(caseId);
        c.setVerdict(v);
        if (NewState.NAME.equals(c.getState().name())) {
            c.startInvestigation();
        }
        warnings.clear();
        save(c);
        return c;
    }

    /** Stores the case's enriched indicators and saves it. */
    public synchronized Case recordIocs(String caseId, List<Ioc> iocs) {
        Case c = getCase(caseId);
        c.setIocs(iocs);
        warnings.clear();
        save(c);
        return c;
    }

    /** Number of cases in each state, always listing all four states in lifecycle order. */
    public synchronized Map<String, Integer> countByState() {
        Map<String, Integer> counts = new LinkedHashMap<>();
        for (String name : List.of(NewState.NAME, InvestigatingState.NAME, EscalatedState.NAME, ClosedState.NAME)) {
            counts.put(name, 0);
        }
        for (Case c : cases.values()) {
            counts.merge(c.getState().name(), 1, Integer::sum);
        }
        return counts;
    }

    /** All cases, highest priority first. */
    public synchronized List<Case> listCases() {
        return sortByPriority(new ArrayList<>(cases.values()));
    }

    /**
     * Writes the case to its JSON file. On failure the case stays in memory and a warning
     * is recorded (see {@link #getWarnings()}).
     *
     * @return true if the case was saved
     */
    public synchronized boolean save(Case c) {
        try {
            Files.createDirectories(casesDir);
            Path file = casesDir.resolve(c.getId() + ".json");
            Path tmp = casesDir.resolve(c.getId() + ".json.tmp");
            mapper.writerWithDefaultPrettyPrinter().writeValue(tmp.toFile(), c.snapshot());
            Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING);
            return true;
        } catch (IOException e) {
            warnings.add("Case " + c.getId() + " could not be saved (" + e.getMessage() + "); it is kept in memory only");
            return false;
        }
    }

    /** Problems from the last load or createCases call, for the GUI and CLI to show. */
    public synchronized List<String> getWarnings() {
        return List.copyOf(warnings);
    }

    /** Groups related findings (see {@link #related}); the input should be sorted by time. */
    List<List<Finding>> groupFindings(List<Finding> findings) {
        List<List<Finding>> groups = new ArrayList<>();
        for (Finding f : findings) {
            List<Finding> match = null;
            for (List<Finding> g : groups) {
                if (related(g, f)) {
                    match = g;
                    break;
                }
            }
            if (match == null) {
                match = new ArrayList<>();
                groups.add(match);
            }
            match.add(f);
        }
        return groups;
    }

    /**
     * Priority from 0 to 100: 20 points per severity level (LOW 20 ... CRITICAL 80), plus 5 for
     * each additional finding (at most 15) and 5 when more than one detector agrees.
     */
    static int computePriority(Case c) {
        int score = c.getSeverity().weight() * 20;
        score += Math.min(15, 5 * (c.getFindings().size() - 1));
        long detectors = c.getFindings().stream().map(Finding::detector).distinct().count();
        if (detectors > 1) {
            score += 5;
        }
        return Math.min(100, score);
    }

    /**
     * A finding is related to a group when it is within 60 minutes of the group's time span
     * and has the same source IP as one of its findings, or, if it has no IP, the same host.
     */
    static boolean related(List<Finding> group, Finding f) {
        Instant first = group.stream().map(Finding::firstSeen).min(Comparator.naturalOrder()).orElseThrow();
        Instant last = group.stream().map(Finding::lastSeen).max(Comparator.naturalOrder()).orElseThrow();
        boolean close = !f.firstSeen().isAfter(last.plus(GROUP_WINDOW))
                && !f.lastSeen().isBefore(first.minus(GROUP_WINDOW));
        if (!close) {
            return false;
        }
        if (f.srcIp() != null) {
            return group.stream().anyMatch(g -> f.srcIp().equals(g.srcIp()));
        }
        if (f.host() != null) {
            return group.stream().anyMatch(g -> f.host().equals(g.host()));
        }
        return false;
    }

    /** The first open case related to the finding; closed cases are never extended. */
    private Case findRelatedCase(Finding f) {
        for (Case c : cases.values()) {
            if (!c.isClosed() && related(c.getFindings(), f)) {
                return c;
            }
        }
        return null;
    }

    /** True if some case already has a finding from the same detector with the same evidence. */
    private boolean isRecorded(Finding f) {
        String key = evidenceKey(f);
        return cases.values().stream()
                .flatMap(c -> c.getFindings().stream())
                .anyMatch(existing -> evidenceKey(existing).equals(key));
    }

    private static String evidenceKey(Finding f) {
        return f.detector() + "|" + f.events().stream().map(SecurityEvent::id).sorted().collect(Collectors.joining(","));
    }

    private static String titleFor(List<Finding> group) {
        Finding top = group.get(0);
        for (Finding f : group) {
            if (f.severity().compareTo(top.severity()) > 0) {
                top = f;
            }
        }
        return group.size() == 1 ? top.title() : top.title() + " (+" + (group.size() - 1) + " related)";
    }

    private String nextId() {
        lastNumber++;
        return String.format(Locale.ROOT, "CASE-%04d", lastNumber);
    }

    private static int number(String id) {
        Matcher m = ID_PATTERN.matcher(id);
        return m.matches() ? Integer.parseInt(m.group(1)) : 0;
    }

    private static List<Case> sortByPriority(List<Case> list) {
        list.sort(Comparator.comparingInt(Case::getPriority).reversed().thenComparing(Case::getId));
        return list;
    }
}
