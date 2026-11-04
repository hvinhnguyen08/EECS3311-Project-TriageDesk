package ca.yorku.triagedesk.gui;

import ca.yorku.triagedesk.domain.Case;

/** One row of the case table: a read-only snapshot of the fields the table shows. */
public class CaseRow {

    private final String id;
    private final String state;
    private final String severity;
    private final int priority;
    private final int findings;
    private final String title;

    public CaseRow(Case c) {
        this.id = c.getId();
        this.state = c.getState().name();
        this.severity = c.getSeverity().name();
        this.priority = c.getPriority();
        this.findings = c.getFindings().size();
        this.title = c.getTitle();
    }

    public String getId() { return id; }
    public String getState() { return state; }
    public String getSeverity() { return severity; }
    public int getPriority() { return priority; }
    public int getFindings() { return findings; }
    public String getTitle() { return title; }
}
