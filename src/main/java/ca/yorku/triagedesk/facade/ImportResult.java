package ca.yorku.triagedesk.facade;

/** Outcome of importing one file: its batch ID (the file name), detected format, and line counts. */
public record ImportResult(String batchId, String format, int imported, int skipped) {
}
