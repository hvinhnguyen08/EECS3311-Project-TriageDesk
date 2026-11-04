package ca.yorku.triagedesk.agent;

import ca.yorku.triagedesk.domain.SecurityEvent;
import ca.yorku.triagedesk.ingest.EventStore;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Concrete command "search_events": finds imported events matching the filters. Receiver: EventStore. */
public class SearchEventsTool implements Tool {

    public static final String NAME = "search_events";
    static final int DEFAULT_LIMIT = 20;
    static final int MAX_LIMIT = 50;

    private final EventStore store;

    public SearchEventsTool(EventStore store) {
        this.store = store;
    }

    @Override
    public String name() {
        return NAME;
    }

    @Override
    public String description() {
        return "Find imported log events that match all the given filters (oldest first). Returns the total number"
                + " of matches and up to 'limit' events with their time, host, user, source IP, category and message.";
    }

    @Override
    public String parameters() {
        ObjectNode schema = EventToolSupport.filterSchema();
        EventToolSupport.integer((ObjectNode) schema.get("properties"), "limit",
                "Maximum number of events to return (default " + DEFAULT_LIMIT + ", max " + MAX_LIMIT + ")");
        return schema.toString();
    }

    @Override
    public String execute(String argsJson) {
        Map<String, String> criteria = ToolArgs.parse(argsJson);
        int limit = ToolArgs.takeInt(criteria, "limit", DEFAULT_LIMIT, MAX_LIMIT);
        List<SecurityEvent> matches = store.search(criteria);

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("total", matches.size());
        result.put("returned", Math.min(limit, matches.size()));
        result.put("events", matches.stream().limit(limit).map(EventToolSupport::summarise).toList());
        return EventToolSupport.toJson(result);
    }
}
