package ca.yorku.triagedesk.gui;

import java.util.concurrent.Callable;
import java.util.function.Consumer;

/**
 * Runs work away from the user-interface thread and reports the result back on it. The
 * JavaFX implementation keeps the window responsive during AI and network calls; tests use
 * a synchronous implementation so controllers can be checked without a window.
 */
public interface UiTasks {

    <T> void run(Callable<T> work, Consumer<T> onSuccess, Consumer<Throwable> onFailure);
}
