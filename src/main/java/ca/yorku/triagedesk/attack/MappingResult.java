package ca.yorku.triagedesk.attack;

import ca.yorku.triagedesk.domain.AttackTechnique;
import java.util.List;

/**
 * Outcome of mapping a case to ATT&CK: the techniques stored on the case, which IDs came
 * from the detections and which from the agent, and the IDs that were dropped because they
 * are not in the catalogue.
 */
public record MappingResult(List<AttackTechnique> techniques, List<String> fromDetections,
                            List<String> fromAgent, List<String> rejected) {

    public MappingResult {
        techniques = List.copyOf(techniques);
        fromDetections = List.copyOf(fromDetections);
        fromAgent = List.copyOf(fromAgent);
        rejected = List.copyOf(rejected);
    }

    public String sourceOf(String id) {
        return fromDetections.contains(id) ? "detection" : fromAgent.contains(id) ? "AI" : "";
    }
}
