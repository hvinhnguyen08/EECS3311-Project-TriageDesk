package ca.yorku.triagedesk.gui;

import ca.yorku.triagedesk.agent.TokenUsage;
import ca.yorku.triagedesk.attack.MappingResult;
import ca.yorku.triagedesk.casemgmt.CaseActions;
import ca.yorku.triagedesk.domain.Case;
import ca.yorku.triagedesk.domain.Ioc;
import ca.yorku.triagedesk.domain.ResponsePlan;
import ca.yorku.triagedesk.domain.TriageVerdict;
import ca.yorku.triagedesk.facade.ReportResult;
import ca.yorku.triagedesk.facade.SocAssistant;
import java.nio.file.Path;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.concurrent.Callable;
import java.util.function.Function;

/**
 * Controller of the case screen (MVC). Each action calls the facade in the background,
 * re-renders the case from the facade's state, and tells the app that the case changed so
 * the case table can update.
 */
public class CaseController {

    private final SocAssistant assistant;
    private final CaseView view;
    private final UiTasks tasks;
    private final String caseId;
    private final Path reportDir;
    private final Runnable onCaseChanged;

    /**
     * @param reportDir     where reports are written
     * @param onCaseChanged called after every change, for example to refresh the case table
     */
    public CaseController(SocAssistant assistant, CaseView view, UiTasks tasks, String caseId, Path reportDir,
                          Runnable onCaseChanged) {
        this.assistant = assistant;
        this.view = view;
        this.tasks = tasks;
        this.caseId = caseId;
        this.reportDir = reportDir;
        this.onCaseChanged = onCaseChanged;
        view.setOnTriage(this::onTriage);
        view.setOnEnrich(this::onEnrich);
        view.setOnMapAttack(this::onMapAttack);
        view.setOnChangeStatus(this::onChangeStatus);
        view.setOnAddNote(this::onAddNote);
        view.setOnRecommendResponse(this::onRecommendResponse);
        view.setOnStepDone(this::onStepDone);
        view.setOnGenerateReport(this::onGenerateReport);
    }

    public void load() {
        tasks.run(() -> assistant.getCase(caseId), view::render, e -> view.showError(MainController.message(e)));
    }

    // F06

    public void onTriage() {
        change("The AI agent is investigating " + caseId + "...", () -> assistant.triageCase(caseId),
                (TriageVerdict v) -> String.format(Locale.ROOT, "AI verdict: %s (confidence %.2f), %d tool calls.%s",
                        v.verdict(), v.confidence(), v.toolTrace().size(), usage()));
    }

    // F07

    public void onEnrich() {
        change("Looking up indicators...", () -> assistant.enrichIocs(caseId), (List<Ioc> iocs) -> {
            if (iocs.isEmpty()) {
                return "No indicators found.";
            }
            List<String> providers = assistant.threatIntelProviders();
            return iocs.size() + " indicator(s); " + (providers.isEmpty()
                    ? "no threat-intel provider configured (set ABUSEIPDB_API_KEY or VIRUSTOTAL_API_KEY), so they have no scores."
                    : "checked with " + String.join(", ", providers) + ".");
        });
    }

    // F08

    public void onMapAttack(boolean askAgent) {
        change(askAgent ? "Mapping to ATT&CK with the AI agent..." : "Mapping to ATT&CK...",
                () -> assistant.mapAttack(caseId, askAgent), (MappingResult r) -> r.techniques().size()
                        + " technique(s): " + r.fromDetections().size() + " from detections, " + r.fromAgent().size()
                        + " from the AI." + (r.rejected().isEmpty() ? "" : " Ignored (not in the catalogue): "
                        + String.join(", ", r.rejected()) + ".") + (askAgent ? usage() : ""));
    }

    // F09

    public void onChangeStatus(String action) {
        String reason = null;
        String resolution = null;
        if (CaseActions.ESCALATE.equals(action)) {
            Optional<String> r = view.askEscalationReason();
            if (r.isEmpty()) {
                return;
            }
            reason = r.get();
        } else if (CaseActions.CLOSE.equals(action)) {
            Optional<CaseView.CloseRequest> r = view.askClose();
            if (r.isEmpty()) {
                return;
            }
            resolution = r.get().resolution();
            reason = r.get().comment();
        }
        String comment = reason;
        String res = resolution;
        change("Updating " + caseId + "...", () -> assistant.changeStatus(caseId, action, res, comment),
                (Case c) -> c.getId() + " is now " + c.getState().name() + ".");
    }

    public void onAddNote(String text) {
        change("Saving note...", () -> assistant.addNote(caseId, text), (Case c) -> {
            view.clearNoteInput();
            return "Note added.";
        });
    }

    // F10

    public void onRecommendResponse() {
        change("The AI agent is preparing a response plan...", () -> assistant.recommendResponse(caseId),
                (ResponsePlan p) -> p.getSteps().size() + " response step(s)." + usage());
    }

    public void onStepDone(int stepNumber) {
        change("Updating the response plan...", () -> assistant.markStepDone(caseId, stepNumber),
                (Case c) -> "Step " + stepNumber + " done.");
    }

    // F11

    public void onGenerateReport() {
        view.setBusy(true, "Writing the incident report...");
        tasks.run(() -> assistant.generateReport(caseId, reportDir.resolve(caseId + ".md")), (ReportResult r) -> {
            view.setBusy(false, "");
            view.showReportPath(r.path(), r.warning());
            view.showMessage("Report written to " + r.path().toAbsolutePath().normalize() + (r.aiNarrative() ? usage() : ""));
        }, this::failed);
    }

    /**
     * Runs one change in the background; on success re-renders the case, shows the message
     * built from the result and notifies the app.
     */
    private <T> void change(String busyText, Callable<T> work, Function<T, String> message) {
        view.setBusy(true, busyText);
        tasks.run(() -> {
            T result = work.call();
            return new Changed<>(result, assistant.getCase(caseId));
        }, changed -> {
            view.setBusy(false, "");
            view.render(changed.updated());
            view.showMessage(message.apply(changed.result()));
            onCaseChanged.run();
        }, this::failed);
    }

    private void failed(Throwable e) {
        view.setBusy(false, "");
        view.showError(MainController.message(e));
        // The facade leaves the case unchanged on failure; re-render in case the view shows stale input.
        load();
    }

    private String usage() {
        TokenUsage u = assistant.getLastUsage();
        return u.modelCalls() == 0 ? "" : " (" + u.modelCalls() + " model call(s), " + u.promptTokens() + " + "
                + u.completionTokens() + " tokens)";
    }

    private record Changed<T>(T result, Case updated) {
    }
}
