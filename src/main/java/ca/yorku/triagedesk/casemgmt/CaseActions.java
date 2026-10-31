package ca.yorku.triagedesk.casemgmt;

import java.util.List;

/** Names of the lifecycle actions accepted by {@link CaseManager#applyAction}, shared by the GUI and CLI. */
public final class CaseActions {

    public static final String START = "start";
    public static final String ESCALATE = "escalate";
    public static final String CLOSE = "close";
    public static final String REOPEN = "reopen";

    public static final List<String> ALL = List.of(START, ESCALATE, CLOSE, REOPEN);

    private CaseActions() {
    }
}
