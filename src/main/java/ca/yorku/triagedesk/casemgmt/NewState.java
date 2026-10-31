package ca.yorku.triagedesk.casemgmt;

import ca.yorku.triagedesk.domain.Case;
import java.util.List;

/** A case nobody has worked on yet. It can be investigated, or closed directly (for example an obvious false positive). */
public class NewState extends CaseState {

    public static final String NAME = "NEW";

    @Override
    public void startInvestigation(Case c) {
        c.setState(new InvestigatingState());
        c.recordHistory("Investigation started");
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
        return List.of(CaseActions.START, CaseActions.CLOSE);
    }
}
