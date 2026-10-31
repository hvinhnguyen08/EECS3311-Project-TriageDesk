@echo off
rem Runs the TriageDesk CLI on Windows. Build it first with: mvn package
java -jar "%~dp0target\triagedesk.jar" %*
