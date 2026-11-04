package ca.yorku.triagedesk.gui;

import ca.yorku.triagedesk.domain.Case;
import java.nio.file.Path;
import java.util.Optional;
import java.util.function.Consumer;
import java.util.function.IntConsumer;

/**
 * View of one case (MVC): its findings, evidence, AI verdict, response plan, indicators,
 * ATT&CK techniques, notes and history, plus the analyst's actions on it.
 */
public interface CaseView {

    /** How the analyst wants to close a case. */
    record CloseRequest(String resolution, String comment) {
    }

    /** Shows the whole case; which status buttons are enabled follows its state. */
    void render(Case c);

    void showReportPath(Path report, String warning);

    void showMessage(String message);

    void showError(String message);

    void setBusy(boolean busy, String what);

    /** Asks for the escalation reason; empty if cancelled. */
    Optional<String> askEscalationReason();

    /** Asks for the resolution and closing comment; empty if cancelled. */
    Optional<CloseRequest> askClose();

    void clearNoteInput();

    void setOnTriage(Runnable handler);

    void setOnEnrich(Runnable handler);

    /** Called with true if the analyst also wants AI suggestions. */
    void setOnMapAttack(Consumer<Boolean> handler);

    /** Called with start, escalate, close or reopen. */
    void setOnChangeStatus(Consumer<String> handler);

    void setOnAddNote(Consumer<String> handler);

    void setOnRecommendResponse(Runnable handler);

    /** Called with the 1-based number of the step the analyst ticked. */
    void setOnStepDone(IntConsumer handler);

    void setOnGenerateReport(Runnable handler);
}
