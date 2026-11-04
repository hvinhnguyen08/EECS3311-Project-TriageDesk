package ca.yorku.triagedesk.agent;

import ca.yorku.triagedesk.domain.Ioc;
import ca.yorku.triagedesk.intel.EnrichmentService;
import ca.yorku.triagedesk.intel.IocExtractor;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.util.LinkedHashMap;
import java.util.Map;

/** Concrete command "lookup_ioc": reputation of an IP, domain, URL or hash. Receiver: EnrichmentService. */
public class LookupIocTool implements Tool {

    public static final String NAME = "lookup_ioc";

    private final EnrichmentService enrichment;

    public LookupIocTool(EnrichmentService enrichment) {
        this.enrichment = enrichment;
    }

    @Override
    public String name() {
        return NAME;
    }

    @Override
    public String description() {
        return "Look up the reputation of an IP address, domain, URL or file hash with threat-intelligence services"
                + " (AbuseIPDB, VirusTotal). Returns a score from 0 (clean or unknown) to 100 (malicious), or null if"
                + " no service could rate it. Private IP addresses are never sent out.";
    }

    @Override
    public String parameters() {
        ObjectNode schema = ca.yorku.triagedesk.util.Json.mapper().createObjectNode();
        schema.put("type", "object");
        EventToolSupport.string(schema.putObject("properties"), "value", "The IP address, domain, URL or hash to check");
        schema.putArray("required").add("value");
        return schema.toString();
    }

    @Override
    public String execute(String argsJson) {
        String value = ToolArgs.parse(argsJson).get("value");
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("'value' is required, for example {\"value\":\"203.0.113.7\"}");
        }
        String v = value.strip();
        Ioc result = enrichment.lookup(Ioc.unscored(IocExtractor.classify(v), v));
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("type", result.type());
        out.put("value", result.value());
        out.put("score", result.isScored() ? result.score() : null);
        out.put("source", result.source());
        return EventToolSupport.toJson(out);
    }
}
