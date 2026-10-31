package ca.yorku.triagedesk.casemgmt;

import ca.yorku.triagedesk.domain.Case;
import java.util.List;

/** Handed to L2 / incident response. The only way forward is to close it. */
public class EscalatedState extends CaseState {

    public static final String NAME = "ESCALATED";

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
        return List.of(CaseActions.CLOSE);
    }
}
