package ca.yorku.triagedesk.intel;

/** A lookup failed (missing or rejected key, rate limit, timeout). The message never contains the API key. */
public class ThreatIntelException extends RuntimeException {

    public ThreatIntelException(String message) {
        super(message);
    }

    public ThreatIntelException(String message, Throwable cause) {
        super(message, cause);
    }
}
