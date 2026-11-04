package ca.yorku.triagedesk.gui;

import java.util.concurrent.Callable;
import java.util.function.Consumer;

/** Runs the work immediately on the calling thread, so controller tests need no JavaFX thread. */
class DirectUiTasks implements UiTasks {

    @Override
    public <T> void run(Callable<T> work, Consumer<T> onSuccess, Consumer<Throwable> onFailure) {
        T result;
        try {
            result = work.call();
        } catch (Exception e) {
            onFailure.accept(e);
            return;
        }
        onSuccess.accept(result);
    }
}
