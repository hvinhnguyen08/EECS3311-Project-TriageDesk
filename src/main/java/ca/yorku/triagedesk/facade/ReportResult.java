package ca.yorku.triagedesk.facade;

import java.nio.file.Path;

/** Where the incident report was written, and why the AI narrative is missing if it is. */
public record ReportResult(Path path, boolean aiNarrative, String warning) {
}
