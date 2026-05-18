@echo off
setlocal
set DIR=%~dp0
if exist "%DIR%gradle\wrapper\gradle-wrapper.jar" (
  java -jar "%DIR%gradle\wrapper\gradle-wrapper.jar" %*
) else (
  echo Gradle wrapper JAR not found. Run "gradle wrapper" on a machine with Gradle to generate the wrapper.
  exit /b 1
)
