package ca.yorku.triagedesk.gui;

import java.awt.image.BufferedImage;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;
import javafx.application.Platform;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.image.PixelReader;
import javafx.scene.image.WritableImage;
import javax.imageio.ImageIO;

/**
 * Renders a JavaFX screen to a PNG in target/gui-snapshots so its layout can be reviewed
 * without clicking through the app. Used by tests that run only with -Dgui.snapshots=true,
 * because they need a display.
 */
final class GuiSnapshots {

    static final boolean ENABLED = Boolean.getBoolean("gui.snapshots");
    private static boolean started;

    private GuiSnapshots() {
    }

    static synchronized void startToolkit() throws InterruptedException {
        if (started) {
            return;
        }
        CountDownLatch latch = new CountDownLatch(1);
        Platform.startup(latch::countDown);
        latch.await(10, TimeUnit.SECONDS);
        started = true;
    }

    /** Builds the screen on the JavaFX thread, renders it at the given size and saves it. */
    static Path save(String name, Supplier<Parent> screen, int width, int height) throws Exception {
        startToolkit();
        AtomicReference<WritableImage> image = new AtomicReference<>();
        AtomicReference<Throwable> error = new AtomicReference<>();
        CountDownLatch done = new CountDownLatch(1);
        Platform.runLater(() -> {
            try {
                Scene scene = new Scene(screen.get(), width, height);
                scene.getStylesheets().add(GuiSnapshots.class.getResource("/gui/triagedesk.css").toExternalForm());
                scene.getRoot().applyCss();
                scene.getRoot().layout();
                image.set(scene.snapshot(null));
            } catch (Throwable t) {
                error.set(t);
            } finally {
                done.countDown();
            }
        });
        done.await(20, TimeUnit.SECONDS);
        if (error.get() != null) {
            throw new IllegalStateException("Rendering failed", error.get());
        }
        Path out = Path.of("target", "gui-snapshots", name + ".png");
        Files.createDirectories(out.getParent());
        write(image.get(), out);
        return out;
    }

    private static void write(WritableImage img, Path out) {
        int w = (int) img.getWidth();
        int h = (int) img.getHeight();
        BufferedImage buffered = new BufferedImage(w, h, BufferedImage.TYPE_INT_ARGB);
        PixelReader pixels = img.getPixelReader();
        for (int y = 0; y < h; y++) {
            for (int x = 0; x < w; x++) {
                buffered.setRGB(x, y, pixels.getArgb(x, y));
            }
        }
        try {
            ImageIO.write(buffered, "png", out.toFile());
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
