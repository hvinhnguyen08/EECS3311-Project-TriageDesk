package ca.yorku.triagedesk.detect;

import ca.yorku.triagedesk.domain.Finding;
import ca.yorku.triagedesk.domain.SecurityEvent;
import java.util.List;

/**
 * Strategy interface: one detection rule over the imported events. DetectionEngine
 * runs every registered detector without knowing what each one looks for.
 */
public interface Detector {

    List<Finding> detect(List<SecurityEvent> events);

    /** Short name stored on each finding and used in error messages. */
    String name();
}
