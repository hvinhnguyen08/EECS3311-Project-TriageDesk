package ca.yorku.triagedesk.agent;

import ca.yorku.triagedesk.ingest.EventStore;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.util.LinkedHashMap;
import java.util.Map;

/** Concrete command "count_by": counts matching events grouped by one field. Receiver: EventStore. */
public class CountByTool implements Tool {

    public static final String NAME = "count_by";
    static final int DEFAULT_TOP = 10;
    static final int MAX_TOP = 25;

    private final EventStore store;

    public CountByTool(EventStore store) {
        this.store = store;
    }

    @Override
    public String name() {
        return NAME;
    }

    @Override
    public String description() {
        return "Count the imported events that match the filters, grouped by one field, largest count first."
                + " Use it for questions like 'which IPs failed to log in most'.";
    }

    @Override
    public String parameters() {
        ObjectNode schema = EventToolSupport.filterSchema();
        ObjectNode props = (ObjectNode) schema.get("properties");
        EventToolSupport.string(props, "field", "Field to group by: srcIp, user, host, category, source, ruleId,"
                + " batchId, or an attribute such as status, path, userAgent or command");
        EventToolSupport.integer(props, "top", "How many groups to return (default " + DEFAULT_TOP + ", max " + MAX_TOP + ")");
        schema.putArray("required").add("field");
        return schema.toString();
    }

    @Override
    public String execute(String argsJson) {
        Map<String, String> criteria = ToolArgs.parse(argsJson);
        String field = criteria.remove("field");
        if (field == null || field.isBlank()) {
            throw new IllegalArgumentException("'field' is required, for example {\"field\":\"srcIp\"}");
        }
        int top = ToolArgs.takeInt(criteria, "top", DEFAULT_TOP, MAX_TOP);
        Map<String, Integer> counts = store.countBy(field.strip(), criteria);

        Map<String, Integer> topCounts = new LinkedHashMap<>();
        int total = 0;
        for (Map.Entry<String, Integer> e : counts.entrySet()) {
            total += e.getValue();
            if (topCounts.size() < top) {
                topCounts.put(e.getKey(), e.getValue());
            }
        }
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("field", field.strip());
        result.put("eventsCounted", total);
        result.put("distinctValues", counts.size());
        result.put("counts", topCounts);
        return EventToolSupport.toJson(result);
    }
}
