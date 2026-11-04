package ca.yorku.triagedesk.gui;

import ca.yorku.triagedesk.domain.AgentResult;
import ca.yorku.triagedesk.domain.Case;
import java.nio.file.Path;
import java.util.List;
import java.util.function.Consumer;

/**
 * View of the main screen (MVC): imported files, the case queue and the AI log summary.
 * It only displays what the controller gives it and reports the analyst's actions.
 */
public interface MainView {

    /** Asks the analyst which files to import; empty if cancelled. */
    List<Path> showImportDialog();

    void showFiles(List<String> batchIds);

    void showCases(List<Case> cases);

    void showSummary(String batchId, AgentResult result);

    void showMessage(String message);

    void showError(String message);

    /** Shows or hides the "working" indicator with a short description. */
    void setBusy(boolean busy, String what);

    void setOnImport(Runnable handler);

    void setOnRunDetections(Runnable handler);

    /** Called with the selected file's batch ID, or null if none is selected. */
    void setOnSummarize(Consumer<String> handler);

    void setOnOpenCase(Consumer<String> handler);
}
