package ca.yorku.triagedesk.gui;

import ca.yorku.triagedesk.domain.Case;
import ca.yorku.triagedesk.facade.DetectionResult;
import ca.yorku.triagedesk.facade.ImportResult;
import ca.yorku.triagedesk.facade.SocAssistant;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

/**
 * Controller of the main screen (MVC): turns the analyst's actions into SocAssistant calls,
 * runs them in the background and updates the view. It holds no business logic.
 */
public class MainController {

    private final SocAssistant assistant;
    private final MainView view;
    private final UiTasks tasks;
    private final Consumer<String> caseOpener;

    /** @param caseOpener opens the case screen for a case ID */
    public MainController(SocAssistant assistant, MainView view, UiTasks tasks, Consumer<String> caseOpener) {
        this.assistant = assistant;
        this.view = view;
        this.tasks = tasks;
        this.caseOpener = caseOpener;
        view.setOnImport(this::onImport);
        view.setOnRunDetections(this::onRunDetections);
        view.setOnSummarize(this::onSummarize);
        view.setOnOpenCase(this::onOpenCase);
    }

    /** Reloads the file list and the case queue, for example after another screen changed a case. */
    public void refresh() {
        tasks.run(() -> new Snapshot(assistant.listBatches(), assistant.listCases()),
                snap -> {
                    view.showFiles(snap.files());
                    view.showCases(snap.cases());
                },
                e -> view.showError(message(e)));
    }

    // F01, F02

    public void onImport() {
        List<Path> files = view.showImportDialog();
        if (files.isEmpty()) {
            return;
        }
        view.setBusy(true, "Importing " + files.size() + " file(s)...");
        tasks.run(() -> {
            List<String> done = new ArrayList<>();
            List<String> failed = new ArrayList<>();
            for (Path f : files) {
                try {
                    ImportResult r = assistant.importFile(f);
                    done.add(String.format("%s: %d events (%s), %d lines skipped", r.batchId(), r.imported(), r.format(), r.skipped()));
                } catch (RuntimeException e) {
                    failed.add(message(e));
                }
            }
            return new ImportOutcome(done, failed, assistant.listBatches());
        }, outcome -> {
            view.setBusy(false, "");
            if (!outcome.done().isEmpty()) {
                view.showMessage("Imported " + String.join("; ", outcome.done()));
            }
            if (!outcome.failed().isEmpty()) {
                view.showError(String.join("\n", outcome.failed()));
            }
            view.showFiles(outcome.files());
        }, this::failed);
    }

    // F03, F05

    public void onRunDetections() {
        view.setBusy(true, "Running detections...");
        tasks.run(() -> new Detected(assistant.runDetections(), assistant.listCases()), d -> {
            DetectionResult r = d.result();
            view.setBusy(false, "");
            if (r.findings() == 0) {
                view.showMessage("No suspicious activity found.");
            } else if (r.cases().isEmpty()) {
                view.showMessage(r.findings() + " findings; every finding is already part of an existing case.");
            } else {
                view.showMessage(r.findings() + " findings; " + r.cases().size() + " case(s) created or updated.");
            }
            if (!r.warnings().isEmpty()) {
                view.showError(String.join("\n", r.warnings()));
            }
            view.showCases(assistant.listCases());
        }, this::failed);
    }

    // F04

    public void onSummarize(String batchId) {
        if (batchId == null) {
            view.showError("Select an imported file to summarise first.");
            return;
        }
        view.setBusy(true, "The AI agent is summarising " + batchId + "...");
        tasks.run(() -> assistant.summarizeLog(batchId), r -> {
            view.setBusy(false, "");
            view.showSummary(batchId, r);
            view.showMessage("Summary of " + batchId + " ready (" + r.toolTrace().size() + " tool calls).");
        }, this::failed);
    }

    public void onOpenCase(String caseId) {
        if (caseId != null) {
            caseOpener.accept(caseId);
        }
    }

    private void failed(Throwable e) {
        view.setBusy(false, "");
        view.showError(message(e));
    }

    private record Snapshot(List<String> files, List<Case> cases) {
    }

    private record ImportOutcome(List<String> done, List<String> failed, List<String> files) {
    }

    private record Detected(DetectionResult result, List<Case> allCases) {
    }

    static String message(Throwable e) {
        Throwable t = e;
        while (t.getMessage() == null && t.getCause() != null) {
            t = t.getCause();
        }
        return t.getMessage() != null ? t.getMessage() : t.toString();
    }
}
