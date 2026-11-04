package ca.yorku.triagedesk.agent;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ca.yorku.triagedesk.ingest.EventStore;
import ca.yorku.triagedesk.testutil.SampleData;
import ca.yorku.triagedesk.util.Json;
import com.fasterxml.jackson.databind.JsonNode;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class EventToolsTest {

    @TempDir
    Path dataDir;

    private SearchEventsTool search;
    private CountByTool countBy;

    @BeforeEach
    void setUp() {
        EventStore store = new EventStore(dataDir);
        store.addEvents(SampleData.all());
        search = new SearchEventsTool(store);
        countBy = new CountByTool(store);
    }

    private static JsonNode json(String s) throws Exception {
        return Json.mapper().readTree(s);
    }

    @Test
    void searchFiltersAndLimits() throws Exception {
        JsonNode r = json(search.execute("{\"srcIp\":\"203.0.113.7\",\"category\":\"auth_failure\",\"source\":\"auth\",\"limit\":3}"));

        assertEquals(13, r.path("total").asInt());
        assertEquals(3, r.path("returned").asInt());
        JsonNode first = r.path("events").get(0);
        assertEquals("2026-10-28T09:14:02Z", first.path("time").asText());
        assertEquals("web01", first.path("host").asText());
        assertTrue(first.path("message").asText().startsWith("Failed password for root"));
    }

    @Test
    void searchAcceptsNumbersAndShowsUsefulAttributes() throws Exception {
        JsonNode wazuh = json(search.execute("{\"minLevel\": 10}"));
        assertEquals(3, wazuh.path("total").asInt());
        assertTrue(wazuh.path("events").get(0).has("mitre"));

        JsonNode web = json(search.execute("{\"srcIp\":\"198.51.100.23\",\"text\":\"sqlmap\",\"source\":\"apache\"}"));
        assertEquals(0, web.path("total").asInt(), "the user agent is not part of the message");
        JsonNode sqli = json(search.execute("{\"srcIp\":\"198.51.100.23\",\"text\":\"UNION\"}"));
        assertEquals("500", sqli.path("events").get(0).path("status").asText());
        assertTrue(sqli.path("events").get(0).path("userAgent").asText().startsWith("sqlmap"));
    }

    @Test
    void limitIsCapped() throws Exception {
        assertEquals(SearchEventsTool.MAX_LIMIT, json(search.execute("{\"limit\":1000}")).path("returned").asInt());
        assertEquals(SearchEventsTool.DEFAULT_LIMIT, json(search.execute("{}")).path("returned").asInt());
    }

    @Test
    void countByGroupsAndReportsTotals() throws Exception {
        JsonNode r = json(countBy.execute("{\"field\":\"srcIp\",\"category\":\"auth_failure\",\"source\":\"auth\",\"top\":2}"));

        assertEquals("srcIp", r.path("field").asText());
        assertEquals(17, r.path("eventsCounted").asInt());
        assertEquals(3, r.path("distinctValues").asInt());
        assertEquals(13, r.path("counts").path("203.0.113.7").asInt());
        assertEquals(2, r.path("counts").size());
    }

    @Test
    void countByAttributeField() throws Exception {
        JsonNode r = json(countBy.execute("{\"field\":\"status\",\"srcIp\":\"198.51.100.23\",\"source\":\"apache\"}"));

        assertEquals(37, r.path("counts").path("404").asInt());
    }

    @Test
    void badArgumentsAreExplained() {
        assertThrows(IllegalArgumentException.class, () -> search.execute("not json"));
        assertThrows(IllegalArgumentException.class, () -> search.execute("[1,2]"));
        assertThrows(IllegalArgumentException.class, () -> search.execute("{\"srcIp\":[\"a\",\"b\"]}"));
        IllegalArgumentException unknown = assertThrows(IllegalArgumentException.class, () -> search.execute("{\"ip\":\"x\"}"));
        assertTrue(unknown.getMessage().contains("srcIp"));
        IllegalArgumentException noField = assertThrows(IllegalArgumentException.class, () -> countBy.execute("{}"));
        assertTrue(noField.getMessage().contains("'field' is required"));
        assertThrows(IllegalArgumentException.class, () -> search.execute("{\"limit\":\"many\"}"));
    }

    @Test
    void registryBuildsValidSpecs() throws Exception {
        ToolRegistry registry = new ToolRegistry().register(search).register(countBy);

        List<String> specs = registry.specs(List.of(CountByTool.NAME));
        JsonNode spec = json(specs.get(0));

        assertEquals("count_by", spec.path("name").asText());
        assertEquals("object", spec.path("parameters").path("type").asText());
        assertEquals("field", spec.path("parameters").path("required").get(0).asText());
        assertTrue(spec.path("parameters").path("properties").has("srcIp"));
        assertFalse(spec.path("parameters").path("properties").has("limit"));
        assertEquals(List.of("search_events", "count_by"), registry.names());
        assertThrows(IllegalArgumentException.class, () -> registry.register(new SearchEventsTool(null)));
        assertThrows(IllegalArgumentException.class, () -> registry.get("lookup_ioc"));
    }
}
