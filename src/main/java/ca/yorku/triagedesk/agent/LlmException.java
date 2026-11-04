package ca.yorku.triagedesk.agent;

/**
 * The model could not be reached or refused the request. The message is safe to show to
 * the analyst (it never contains the API key).
 */
public class LlmException extends RuntimeException {

    public LlmException(String message) {
        super(message);
    }

    public LlmException(String message, Throwable cause) {
        super(message, cause);
    }
}
