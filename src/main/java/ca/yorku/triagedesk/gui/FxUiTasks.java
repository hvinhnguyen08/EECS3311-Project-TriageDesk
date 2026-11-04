package ca.yorku.triagedesk.gui;

import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.Consumer;
import javafx.application.Platform;

/**
 * Runs work on one background thread, so requests reach the facade one at a time in the
 * order the analyst made them, and delivers results on the JavaFX application thread.
 */
public class FxUiTasks implements UiTasks {

    private final ExecutorService worker = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(r, "triagedesk-worker");
        t.setDaemon(true);
        return t;
    });

    @Override
    public <T> void run(Callable<T> work, Consumer<T> onSuccess, Consumer<Throwable> onFailure) {
        worker.submit(() -> {
            try {
                T result = work.call();
                Platform.runLater(() -> onSuccess.accept(result));
            } catch (Throwable e) {
                Platform.runLater(() -> onFailure.accept(e));
            }
        });
    }

    public void shutdown() {
        worker.shutdownNow();
    }
}
