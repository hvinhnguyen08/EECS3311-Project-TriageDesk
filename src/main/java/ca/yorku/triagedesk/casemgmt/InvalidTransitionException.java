package ca.yorku.triagedesk.casemgmt;

/** Thrown when a lifecycle action is not allowed in the case's current state; the case is unchanged. */
public class InvalidTransitionException extends IllegalStateException {

    public InvalidTransitionException(String message) {
        super(message);
    }
}
