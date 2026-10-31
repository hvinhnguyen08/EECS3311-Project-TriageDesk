package ca.yorku.triagedesk.casemgmt;

import ca.yorku.triagedesk.domain.Case;
import ca.yorku.triagedesk.domain.Verdict;
import java.util.List;

/**
 * State of the State pattern for the case lifecycle. Case delegates every lifecycle action
 * to its current state. These defaults refuse the action; each concrete state overrides
 * only the transitions it allows.
 */
public abstract class CaseState {

    public void startInvestigation(Case c) {
        throw refuse("start investigating");
    }

    public void escalate(Case c, String reason) {
        throw refuse("escalate");
    }

    public void close(Case c, String verdict, String comment) {
        throw refuse("close");
    }

    public void reopen(Case c) {
        throw refuse("reopen");
    }

    /** NEW, INVESTIGATING, ESCALATED or CLOSED. */
    public abstract String name();

    /** The actions this state accepts, for error messages and for enabling GUI buttons. */
    public abstract List<String> allowedActions();

    public boolean isClosed() {
        return false;
    }

    /** Rebuilds a state from its saved name; an unknown or missing name gives NEW. */
    public static CaseState fromName(String name) {
        if (name == null) {
            return new NewState();
        }
        return switch (name) {
            case InvestigatingState.NAME -> new InvestigatingState();
            case EscalatedState.NAME -> new EscalatedState();
            case ClosedState.NAME -> new ClosedState();
            default -> new NewState();
        };
    }

    /** Shared by every state that allows closing: validates the input, then moves the case to CLOSED. */
    protected static void closeCase(Case c, String verdict, String comment) {
        Verdict resolution = Verdict.parse(verdict);
        if (resolution == Verdict.NEEDS_REVIEW) {
            throw new IllegalArgumentException("Close the case as true_positive, false_positive or benign"
                    + (verdict == null || verdict.isBlank() ? "" : " (got: " + verdict + ")"));
        }
        if (comment == null || comment.isBlank()) {
            throw new IllegalArgumentException("A comment is required to close a case");
        }
        c.setResolution(resolution);
        c.setState(new ClosedState());
        c.recordHistory("Closed as " + resolution + ": " + comment.strip());
    }

    protected static String requireReason(String reason) {
        if (reason == null || reason.isBlank()) {
            throw new IllegalArgumentException("A reason is required to escalate a case");
        }
        return reason.strip();
    }

    private InvalidTransitionException refuse(String action) {
        return new InvalidTransitionException("Cannot " + action + " a case that is " + name()
                + ". Allowed: " + String.join(", ", allowedActions()));
    }

    @Override
    public String toString() {
        return name();
    }
}
