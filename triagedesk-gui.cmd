@echo off
rem Starts the TriageDesk GUI on Windows. Build it first with: mvn package
java -cp "%~dp0target\triagedesk.jar" ca.yorku.triagedesk.gui.GuiLauncher %*
