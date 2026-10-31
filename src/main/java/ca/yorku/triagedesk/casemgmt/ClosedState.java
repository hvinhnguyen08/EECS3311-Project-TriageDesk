package ca.yorku.triagedesk.casemgmt;

import ca.yorku.triagedesk.domain.Case;
import java.util.List;

/** Finished. A closed case can only be reopened, which puts it back under investigation. */
public class ClosedState extends CaseState {

    public static final String NAME = "CLOSED";

    @Override
    public void reopen(Case c) {
        c.setResolution(null);
        c.setState(new InvestigatingState());
        c.recordHistory("Reopened");
    }

    @Override
    public String name() {
        return NAME;
    }

    @Override
    public List<String> allowedActions() {
        return List.of(CaseActions.REOPEN);
    }

    @Override
    public boolean isClosed() {
        return true;
    }
}
