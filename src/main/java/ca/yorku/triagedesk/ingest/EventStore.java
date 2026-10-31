package ca.yorku.triagedesk.ingest;

import ca.yorku.triagedesk.domain.SecurityEvent;
import ca.yorku.triagedesk.util.Json;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.Predicate;
import java.util.stream.Collectors;

/**
 * All imported events. They are kept in memory and in {@code <dataDir>/events.jsonl},
 * so that separate CLI commands work on the same data. Also the receiver of the agent's
 * search_events and count_by tools.
 */
public class EventStore {

    static final String FILE_NAME = "events.jsonl";

    /** Event fields that can be used as exact-match search criteria and countBy fields. */
    public static final Set<String> FIELDS = Set.of("batchId", "source", "host", "user", "srcIp", "category", "ruleId");

    /** Search criteria that are not plain field matches. */
    public static final Set<String> SPECIAL_CRITERIA = Set.of("text", "since", "until", "minLevel");

    private final List<SecurityEvent> events = new ArrayList<>();
    private final Path dataDir;
    private final ObjectMapper mapper = Json.mapper();

    public EventStore(Path dataDir) {
        this.dataDir = dataDir;
    }

    /** Replaces the in-memory events with the saved ones. Unreadable lines are ignored. */
    public synchronized void load() {
        events.clear();
        Path file = file();
        if (!Files.isRegularFile(file)) {
            return;
        }
        try {
            for (String line : Files.readAllLines(file, StandardCharsets.UTF_8)) {
                if (line.isBlank()) {
                    continue;
                }
                try {
                    events.add(mapper.readValue(line, SecurityEvent.class));
                } catch (JsonProcessingException | RuntimeException e) {
                    // Corrupt line: ignored so the rest of the data still loads.
                }
            }
        } catch (IOException e) {
            throw new UncheckedIOException("Could not read " + file, e);
        }
    }

    /**
     * Adds and saves events. Importing a batch (file) again replaces its earlier events
     * instead of duplicating them.
     */
    public synchronized void addEvents(List<SecurityEvent> newEvents) {
        if (newEvents == null || newEvents.isEmpty()) {
            return;
        }
        Set<String> batches = newEvents.stream().map(SecurityEvent::batchId).collect(Collectors.toSet());
        boolean replacing = events.stream().anyMatch(e -> batches.contains(e.batchId()));
        if (replacing) {
            events.removeIf(e -> batches.contains(e.batchId()));
        }
        events.addAll(newEvents);
        try {
            if (replacing) {
                rewrite();
            } else {
                append(newEvents);
            }
        } catch (IOException e) {
            throw new UncheckedIOException("Could not save events to " + file(), e);
        }
    }

    public synchronized List<SecurityEvent> all() {
        return List.copyOf(events);
    }

    public synchronized List<SecurityEvent> getBatch(String batchId) {
        return events.stream().filter(e -> e.batchId().equals(batchId)).toList();
    }

    /** Batch IDs (imported file names) in import order. */
    public synchronized List<String> batchIds() {
        return List.copyOf(events.stream().map(SecurityEvent::batchId)
                .collect(Collectors.toCollection(LinkedHashSet::new)));
    }

    /**
     * Returns the events matching every criterion. Keys are the names in {@link #FIELDS}
     * (case-insensitive exact match), "text" (substring of the message), "since"/"until"
     * (ISO-8601 times) or "minLevel" (minimum Wazuh rule level). Blank values are ignored.
     *
     * @throws IllegalArgumentException for an unknown key or an invalid value
     */
    public synchronized List<SecurityEvent> search(Map<String, String> criteria) {
        return events.stream().filter(toPredicate(criteria)).toList();
    }

    /**
     * Counts the matching events grouped by a field, largest count first. The field is one of
     * {@link #FIELDS} or an event attribute such as "status" or "path". Events without a value
     * for the field are not counted.
     */
    public synchronized Map<String, Integer> countBy(String field, Map<String, String> criteria) {
        if (field == null || field.isBlank()) {
            throw new IllegalArgumentException("countBy needs a field name");
        }
        Map<String, Integer> counts = new HashMap<>();
        for (SecurityEvent e : search(criteria)) {
            String value = fieldValue(e, field);
            if (value != null) {
                counts.merge(value, 1, Integer::sum);
            }
        }
        Map<String, Integer> sorted = new LinkedHashMap<>();
        counts.entrySet().stream()
                .sorted(Map.Entry.<String, Integer>comparingByValue(Comparator.reverseOrder())
                        .thenComparing(Map.Entry.<String, Integer>comparingByKey()))
                .forEach(en -> sorted.put(en.getKey(), en.getValue()));
        return sorted;
    }

    public synchronized int size() {
        return events.size();
    }

    static String fieldValue(SecurityEvent e, String field) {
        return switch (field) {
            case "batchId" -> e.batchId();
            case "source" -> e.source();
            case "host" -> e.host();
            case "user" -> e.user();
            case "srcIp" -> e.srcIp();
            case "category" -> e.category();
            case "ruleId" -> e.ruleId();
            default -> e.attribute(field);
        };
    }

    private static Predicate<SecurityEvent> toPredicate(Map<String, String> criteria) {
        Predicate<SecurityEvent> result = e -> true;
        if (criteria == null) {
            return result;
        }
        for (Map.Entry<String, String> c : criteria.entrySet()) {
            String key = c.getKey();
            if (c.getValue() == null || c.getValue().isBlank()) {
                continue;
            }
            String value = c.getValue().strip();
            Predicate<SecurityEvent> next = switch (key) {
                case "text" -> {
                    String needle = value.toLowerCase(Locale.ROOT);
                    yield e -> e.message().toLowerCase(Locale.ROOT).contains(needle)
                            || e.attribute("fullLog") != null
                                && e.attribute("fullLog").toLowerCase(Locale.ROOT).contains(needle);
                }
                case "since" -> {
                    Instant since = parseTime(key, value);
                    yield e -> !e.timestamp().isBefore(since);
                }
                case "until" -> {
                    Instant until = parseTime(key, value);
                    yield e -> !e.timestamp().isAfter(until);
                }
                case "minLevel" -> {
                    int min = parseLevel(value);
                    yield e -> e.ruleLevel() >= min;
                }
                default -> {
                    if (!FIELDS.contains(key)) {
                        throw new IllegalArgumentException("Unknown search criterion '" + key
                                + "'. Allowed: " + new TreeSet<>(FIELDS) + " and " + new TreeSet<>(SPECIAL_CRITERIA));
                    }
                    yield e -> value.equalsIgnoreCase(fieldValue(e, key));
                }
            };
            result = result.and(next);
        }
        return result;
    }

    private static Instant parseTime(String key, String value) {
        try {
            return Instant.parse(value);
        } catch (DateTimeParseException e) {
            try {
                return OffsetDateTime.parse(value).toInstant();
            } catch (DateTimeParseException e2) {
                throw new IllegalArgumentException("Invalid time for '" + key + "': " + value
                        + " (use ISO-8601, for example 2026-10-28T09:00:00Z)");
            }
        }
    }

    private static int parseLevel(String value) {
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("minLevel must be a number: " + value);
        }
    }

    private Path file() {
        return dataDir.resolve(FILE_NAME);
    }

    private void append(List<SecurityEvent> newEvents) throws IOException {
        Files.createDirectories(dataDir);
        try (BufferedWriter w = Files.newBufferedWriter(file(), StandardCharsets.UTF_8,
                StandardOpenOption.CREATE, StandardOpenOption.APPEND)) {
            for (SecurityEvent e : newEvents) {
                w.write(mapper.writeValueAsString(e));
                w.newLine();
            }
        }
    }

    private void rewrite() throws IOException {
        Files.createDirectories(dataDir);
        Path tmp = dataDir.resolve(FILE_NAME + ".tmp");
        try (BufferedWriter w = Files.newBufferedWriter(tmp, StandardCharsets.UTF_8)) {
            for (SecurityEvent e : events) {
                w.write(mapper.writeValueAsString(e));
                w.newLine();
            }
        }
        Files.move(tmp, file(), StandardCopyOption.REPLACE_EXISTING);
    }
}
