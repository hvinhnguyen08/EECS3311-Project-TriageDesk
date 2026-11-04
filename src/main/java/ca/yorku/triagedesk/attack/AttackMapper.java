package ca.yorku.triagedesk.attack;

import ca.yorku.triagedesk.domain.AttackTechnique;
import ca.yorku.triagedesk.domain.Case;
import ca.yorku.triagedesk.domain.Finding;
import ca.yorku.triagedesk.util.Json;
import com.fasterxml.jackson.databind.JsonNode;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;

/**
 * Maps a case to MITRE ATT&CK techniques (F08, hybrid). Technique IDs attached by the
 * detections and Wazuh rules are resolved in the bundled catalogue; when there are none, or
 * when the analyst asks for it, the agent suggests IDs. Only IDs found in the catalogue are
 * kept, so the model cannot add techniques that do not exist.
 */
public class AttackMapper {

    static final String CATALOGUE_RESOURCE = "/attack/enterprise-attack-subset.json";

    private final Map<String, AttackTechnique> catalogue;

    public AttackMapper(Map<String, AttackTechnique> catalogue) {
        this.catalogue = new LinkedHashMap<>(catalogue);
    }

    /** Loads the technique subset bundled in the application. */
    public static AttackMapper loadBundled() {
        try (InputStream in = AttackMapper.class.getResourceAsStream(CATALOGUE_RESOURCE)) {
            if (in == null) {
                throw new IllegalStateException("ATT&CK catalogue not found: " + CATALOGUE_RESOURCE);
            }
            Map<String, AttackTechnique> techniques = new LinkedHashMap<>();
            for (JsonNode t : Json.mapper().readTree(in).path("techniques")) {
                List<String> tactics = new ArrayList<>();
                t.path("tactics").forEach(n -> tactics.add(n.asText()));
                AttackTechnique technique = new AttackTechnique(t.path("id").asText(), t.path("name").asText(),
                        String.join(", ", tactics));
                techniques.put(technique.id(), technique);
            }
            return new AttackMapper(techniques);
        } catch (IOException e) {
            throw new UncheckedIOException("Could not read the ATT&CK catalogue", e);
        }
    }

    /** The catalogue entry for an ID such as "t1110.001", or null if it is not in the catalogue. */
    public AttackTechnique find(String id) {
        return id == null ? null : catalogue.get(id.strip().toUpperCase(Locale.ROOT));
    }

    public int size() {
        return catalogue.size();
    }

    /**
     * Maps the case. The detections' IDs are always used; the suggester (the agent) is asked
     * only when there are none, or when {@code askAgent} is true.
     *
     * @param suggester returns candidate technique IDs for a case; may throw if the AI service fails
     * @throws IllegalStateException if the case has no IDs and the agent could not be asked
     */
    public MappingResult map(Case c, boolean askAgent, Function<Case, List<String>> suggester) {
        Set<String> detectionIds = new LinkedHashSet<>();
        for (Finding f : c.getFindings()) {
            f.techniqueIds().forEach(id -> detectionIds.add(id.strip().toUpperCase(Locale.ROOT)));
        }

        Map<String, AttackTechnique> result = new LinkedHashMap<>();
        List<String> fromDetections = new ArrayList<>();
        List<String> rejected = new ArrayList<>();
        for (String id : detectionIds) {
            AttackTechnique t = find(id);
            if (t != null) {
                result.put(t.id(), t);
                fromDetections.add(t.id());
            } else {
                rejected.add(id);
            }
        }

        List<String> fromAgent = new ArrayList<>();
        if (askAgent || result.isEmpty()) {
            List<String> suggested;
            try {
                suggested = suggester.apply(c);
            } catch (RuntimeException e) {
                if (result.isEmpty()) {
                    throw new IllegalStateException("No mapping available: the case has no technique IDs and the"
                            + " AI suggestion failed (" + e.getMessage() + ")", e);
                }
                throw e;
            }
            for (String raw : suggested) {
                AttackTechnique t = find(raw);
                if (t == null) {
                    rejected.add(raw.strip().toUpperCase(Locale.ROOT));
                } else if (!result.containsKey(t.id())) {
                    result.put(t.id(), t);
                    fromAgent.add(t.id());
                }
            }
        }
        return new MappingResult(new ArrayList<>(result.values()), fromDetections, fromAgent, rejected);
    }
}
