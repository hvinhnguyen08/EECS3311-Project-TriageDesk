package ca.yorku.triagedesk.gui;

import javafx.application.Application;

/**
 * Entry point for the GUI from the single runnable jar. It must not extend Application
 * itself, otherwise Java refuses to start JavaFX from the class path.
 */
public final class GuiLauncher {

    private GuiLauncher() {
    }

    public static void main(String[] args) {
        Application.launch(TriageDeskApp.class, args);
    }
}
