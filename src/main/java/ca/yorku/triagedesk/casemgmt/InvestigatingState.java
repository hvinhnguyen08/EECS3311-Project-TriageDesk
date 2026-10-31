package ca.yorku.triagedesk.casemgmt;

import ca.yorku.triagedesk.domain.Case;
import java.util.List;

/** An analyst is working on the case. It can be escalated to L2 or closed. */
public class InvestigatingState extends CaseState {

    public static final String NAME = "INVESTIGATING";

    @Override
    public void escalate(Case c, String reason) {
        String why = requireReason(reason);
        c.setState(new EscalatedState());
        c.recordHistory("Escalated: " + why);
    }

    @Override
    public void close(Case c, String verdict, String comment) {
        closeCase(c, verdict, comment);
    }

    @Override
    public String name() {
        return NAME;
    }

    @Override
    public List<String> allowedActions() {
        return List.of(CaseActions.ESCALATE, CaseActions.CLOSE);
    }
}
