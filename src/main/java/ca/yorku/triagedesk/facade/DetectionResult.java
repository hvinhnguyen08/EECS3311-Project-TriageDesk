package ca.yorku.triagedesk.facade;

import ca.yorku.triagedesk.domain.Case;
import java.util.List;

/**
 * Outcome of running detections: how many findings the detectors produced, the cases
 * that were created or updated (highest priority first), and any detector or save warnings.
 */
public record DetectionResult(int findings, List<Case> cases, List<String> warnings) {

    public DetectionResult {
        cases = List.copyOf(cases);
        warnings = List.copyOf(warnings);
    }
}
