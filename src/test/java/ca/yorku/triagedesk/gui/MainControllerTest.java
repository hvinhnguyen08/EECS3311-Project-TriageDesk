package ca.yorku.triagedesk.gui;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ca.yorku.triagedesk.agent.LlmReply;
import ca.yorku.triagedesk.agent.MockLlmClient;
import ca.yorku.triagedesk.config.AppConfig;
import ca.yorku.triagedesk.facade.SocAssistant;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class MainControllerTest {

    @TempDir
    Path dataDir;

    private final FakeMainView view = new FakeMainView();
    private final List<String> opened = new ArrayList<>();
    private MockLlmClient llm;

    @BeforeEach
    void setUp() {
        llm = new MockLlmClient(LlmReply.text("auth.log: 35 events, a brute force from 203.0.113.7."));
        SocAssistant assistant = SocAssistant.create(AppConfig.load(null, Map.of()), dataDir, llm);
        new MainController(assistant, view, new DirectUiTasks(), opened::add);
    }

    @Test
    void importShowsCountsErrorsAndTheFileList() {
        view.filesToImport = List.of(Path.of("samples/auth.log"), Path.of("samples/errors/unsupported-format.txt"));

        view.onImport.run();

        assertEquals("Imported auth.log: 35 events (auth), 0 lines skipped", view.lastMessage());
        assertEquals(1, view.errors.size());
        assertTrue(view.errors.get(0).contains("Unsupported file format"));
        assertEquals(List.of("auth.log"), view.files);
        assertEquals(List.of(true, false), view.busyChanges);
    }

    @Test
    void cancelledImportDoesNothing() {
        view.onImport.run();

        assertTrue(view.messages.isEmpty());
        assertTrue(view.busyChanges.isEmpty());
    }

    @Test
    void detectionsFillTheCaseTable() {
        view.onRunDetections.run();
        assertEquals(List.of("Import a file first"), view.errors);

        view.filesToImport = List.of(Path.of("samples/alerts.json"), Path.of("samples/auth.log"), Path.of("samples/access.log"));
        view.onImport.run();
        view.onRunDetections.run();

        assertEquals("8 findings; 3 case(s) created or updated.", view.lastMessage());
        assertEquals(List.of("CASE-0001", "CASE-0003", "CASE-0002"), view.cases.stream().map(c -> c.getId()).toList());

        view.onRunDetections.run();
        assertEquals("8 findings; every finding is already part of an existing case.", view.lastMessage());
    }

    @Test
    void summaryNeedsASelectedFile() {
        view.onSummarize.accept(null);
        assertEquals(List.of("Select an imported file to summarise first."), view.errors);

        view.filesToImport = List.of(Path.of("samples/auth.log"));
        view.onImport.run();
        view.onSummarize.accept("auth.log");

        assertEquals("auth.log: 35 events, a brute force from 203.0.113.7.", view.summary.text());
        assertTrue(view.lastMessage().startsWith("Summary of auth.log ready"));
    }

    @Test
    void aiFailureIsShownAndTheViewIsNotLeftBusy() {
        view.filesToImport = List.of(Path.of("samples/auth.log"));
        view.onImport.run();
        llm.chat(List.of(), List.of());  // use up the only scripted reply
        view.busyChanges.clear();

        view.onSummarize.accept("auth.log");

        assertEquals(List.of("Mock LLM has no scripted reply left"), view.errors);
        assertEquals(List.of(true, false), view.busyChanges);
    }

    @Test
    void doubleClickOpensTheCase() {
        view.onOpenCase.accept("CASE-0001");
        view.onOpenCase.accept(null);

        assertEquals(List.of("CASE-0001"), opened);
    }
}
