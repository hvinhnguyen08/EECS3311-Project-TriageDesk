package ca.yorku.triagedesk.ingest;

/** Thrown when a file is not in any of the supported log formats. */
public class UnsupportedFormatException extends IllegalArgumentException {

    public UnsupportedFormatException(String message) {
        super(message);
    }
}
