package ca.yorku.triagedesk.ingest;

import ca.yorku.triagedesk.domain.SecurityEvent;
import java.util.List;

/**
 * Product of the Factory Method pattern: converts the lines of one log format into
 * normalised events. Malformed lines are skipped, never fatal; the caller can compute
 * the number skipped from the number of non-blank lines.
 */
public interface LogParser {

    List<SecurityEvent> parse(List<String> lines, String batchId);

    /** Event IDs are "batchId:lineNumber", so re-importing a file produces the same IDs. */
    static String eventId(String batchId, int lineNumber) {
        return batchId + ":" + lineNumber;
    }
}
