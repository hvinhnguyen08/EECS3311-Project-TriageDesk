package ca.yorku.triagedesk.gui;

import ca.yorku.triagedesk.domain.Case;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.function.Consumer;
import java.util.function.IntConsumer;

/** Records what the controller shows; dialog answers are preset by the test. */
class FakeCaseView implements CaseView {

    Case rendered;
    Path report;
    String reportWarning;
    Optional<String> escalationReason = Optional.empty();
    Optional<CloseRequest> closeRequest = Optional.empty();
    boolean noteCleared;
    final List<String> messages = new ArrayList<>();
    final List<String> errors = new ArrayList<>();
    final List<Boolean> busyChanges = new ArrayList<>();

    Runnable onTriage;
    Runnable onEnrich;
    Consumer<Boolean> onMapAttack;
    Consumer<String> onChangeStatus;
    Consumer<String> onAddNote;
    Runnable onRecommendResponse;
    IntConsumer onStepDone;
    Runnable onGenerateReport;

    public void render(Case c) { rendered = c; }
    public void showReportPath(Path p, String warning) { report = p; reportWarning = warning; }
    public void showMessage(String message) { messages.add(message); }
    public void showError(String message) { errors.add(message); }
    public void setBusy(boolean busy, String what) { busyChanges.add(busy); }
    public Optional<String> askEscalationReason() { return escalationReason; }
    public Optional<CloseRequest> askClose() { return closeRequest; }
    public void clearNoteInput() { noteCleared = true; }
    public void setOnTriage(Runnable h) { onTriage = h; }
    public void setOnEnrich(Runnable h) { onEnrich = h; }
    public void setOnMapAttack(Consumer<Boolean> h) { onMapAttack = h; }
    public void setOnChangeStatus(Consumer<String> h) { onChangeStatus = h; }
    public void setOnAddNote(Consumer<String> h) { onAddNote = h; }
    public void setOnRecommendResponse(Runnable h) { onRecommendResponse = h; }
    public void setOnStepDone(IntConsumer h) { onStepDone = h; }
    public void setOnGenerateReport(Runnable h) { onGenerateReport = h; }

    String lastMessage() { return messages.get(messages.size() - 1); }
}
