package ca.yorku.triagedesk.gui;

import ca.yorku.triagedesk.domain.AgentResult;
import ca.yorku.triagedesk.domain.Case;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

/** Records what the controller shows and lets the test trigger the analyst's actions. */
class FakeMainView implements MainView {

    List<Path> filesToImport = List.of();
    List<String> files = List.of();
    List<Case> cases = List.of();
    AgentResult summary;
    final List<String> messages = new ArrayList<>();
    final List<String> errors = new ArrayList<>();
    final List<Boolean> busyChanges = new ArrayList<>();
    Runnable onImport;
    Runnable onRunDetections;
    Consumer<String> onSummarize;
    Consumer<String> onOpenCase;

    public List<Path> showImportDialog() { return filesToImport; }
    public void showFiles(List<String> batchIds) { files = batchIds; }
    public void showCases(List<Case> list) { cases = list; }
    public void showSummary(String batchId, AgentResult result) { summary = result; }
    public void showMessage(String message) { messages.add(message); }
    public void showError(String message) { errors.add(message); }
    public void setBusy(boolean busy, String what) { busyChanges.add(busy); }
    public void setOnImport(Runnable handler) { onImport = handler; }
    public void setOnRunDetections(Runnable handler) { onRunDetections = handler; }
    public void setOnSummarize(Consumer<String> handler) { onSummarize = handler; }
    public void setOnOpenCase(Consumer<String> handler) { onOpenCase = handler; }

    String lastMessage() { return messages.get(messages.size() - 1); }
}
