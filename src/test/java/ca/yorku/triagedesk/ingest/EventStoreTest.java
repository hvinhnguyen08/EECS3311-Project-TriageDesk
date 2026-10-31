package ca.yorku.triagedesk.ingest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import ca.yorku.triagedesk.domain.SecurityEvent;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class EventStoreTest {

    private static final Instant T0 = Instant.parse("2026-10-28T09:00:00Z");

    @TempDir
    Path dataDir;

    private EventStore store;

    @BeforeEach
    void setUp() {
        store = new EventStore(dataDir);
    }

    private static SecurityEvent event(String batch, int n, String ip, String category, int minutes) {
        return SecurityEvent.builder(batch + ":" + n, batch, T0.plusSeconds(60L * minutes))
                .source("auth").host("web01").user("root").srcIp(ip)
                .message(category.equals(SecurityEvent.AUTH_FAILURE) ? "Failed password for root" : "Accepted password")
                .category(category).ruleLevel(n).mitreIds(List.of("T1110"))
                .attribute("status", n % 2 == 0 ? "404" : "200")
                .build();
    }

    private void addSampleEvents() {
        store.addEvents(List.of(
                event("auth.log", 1, "203.0.113.7", SecurityEvent.AUTH_FAILURE, 0),
                event("auth.log", 2, "203.0.113.7", SecurityEvent.AUTH_FAILURE, 1),
                event("auth.log", 3, "203.0.113.7", SecurityEvent.AUTH_SUCCESS, 2),
                event("auth.log", 4, "192.168.1.35", SecurityEvent.AUTH_FAILURE, 30)));
    }

    @Test
    void eventsSurviveARestart() {
        addSampleEvents();
        store.addEvents(List.of(event("other.log", 1, "198.51.100.44", SecurityEvent.OTHER, 60)));

        EventStore reloaded = new EventStore(dataDir);
        reloaded.load();

        assertEquals(store.all(), reloaded.all());
        assertEquals(List.of("auth.log", "other.log"), reloaded.batchIds());
    }

    @Test
    void reimportingABatchReplacesItsEvents() {
        addSampleEvents();
        store.addEvents(List.of(event("other.log", 1, "198.51.100.44", SecurityEvent.OTHER, 60)));

        store.addEvents(List.of(event("auth.log", 1, "203.0.113.7", SecurityEvent.AUTH_FAILURE, 0)));

        assertEquals(2, store.size());
        assertEquals(1, store.getBatch("auth.log").size());
        EventStore reloaded = new EventStore(dataDir);
        reloaded.load();
        assertEquals(2, reloaded.size());
    }

    @Test
    void searchCombinesCriteria() {
        addSampleEvents();

        Map<String, String> criteria = new HashMap<>();
        criteria.put("srcIp", "203.0.113.7");
        criteria.put("category", "AUTH_FAILURE");
        criteria.put("text", "failed PASSWORD");
        criteria.put("host", "  ");

        assertEquals(2, store.search(criteria).size());
        assertEquals(4, store.search(null).size());
    }

    @Test
    void searchByTimeAndLevel() {
        addSampleEvents();

        assertEquals(List.of("auth.log:2", "auth.log:3"), ids(store.search(Map.of(
                "since", "2026-10-28T09:01:00Z",
                "until", "2026-10-28T09:02:00Z"))));
        assertEquals(List.of("auth.log:3", "auth.log:4"), ids(store.search(Map.of("minLevel", "3"))));
        assertEquals(1, store.search(Map.of("since", "2026-10-28T05:20:00-04:00")).size());
    }

    @Test
    void invalidCriteriaAreReportedClearly() {
        addSampleEvents();

        IllegalArgumentException unknown = assertThrows(IllegalArgumentException.class,
                () -> store.search(Map.of("ip", "203.0.113.7")));
        assertEquals(true, unknown.getMessage().contains("srcIp"));
        assertThrows(IllegalArgumentException.class, () -> store.search(Map.of("since", "yesterday")));
        assertThrows(IllegalArgumentException.class, () -> store.search(Map.of("minLevel", "high")));
    }

    @Test
    void countByIsSortedLargestFirst() {
        addSampleEvents();

        Map<String, Integer> byIp = store.countBy("srcIp", Map.of("category", SecurityEvent.AUTH_FAILURE));

        assertEquals(List.of("203.0.113.7", "192.168.1.35"), new ArrayList<>(byIp.keySet()));
        assertEquals(2, byIp.get("203.0.113.7"));
        assertEquals(Map.of("404", 2, "200", 2), store.countBy("status", null));
        assertThrows(IllegalArgumentException.class, () -> store.countBy(" ", null));
    }

    @Test
    void corruptLinesInTheDataFileAreIgnored() throws IOException {
        addSampleEvents();
        Path file = dataDir.resolve(EventStore.FILE_NAME);
        Files.writeString(file, Files.readString(file, StandardCharsets.UTF_8) + "{not json\n", StandardCharsets.UTF_8);

        EventStore reloaded = new EventStore(dataDir);
        reloaded.load();

        assertEquals(4, reloaded.size());
    }

    @Test
    void loadWithoutADataFileGivesAnEmptyStore() {
        store.load();

        assertEquals(0, store.size());
        assertEquals(List.of(), store.batchIds());
    }

    private static List<String> ids(List<SecurityEvent> events) {
        return events.stream().map(SecurityEvent::id).toList();
    }
}
