package org.zaproxy.addon.playwrightclient;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import org.json.JSONArray;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.zaproxy.addon.playwrightclient.owasp.OwaspTestFinding;

public class UserScriptRunner {

    private static final Logger LOGGER = LoggerFactory.getLogger(UserScriptRunner.class);

    private final String targetUrl;
    private final String zapProxy;

    public UserScriptRunner(String targetUrl, String zapProxy) {
        this.targetUrl = targetUrl;
        this.zapProxy = zapProxy;
    }

    public List<OwaspTestFinding> runScripts(String scriptsDir) {
        List<OwaspTestFinding> allFindings = new ArrayList<>();
        if (scriptsDir == null || scriptsDir.isEmpty()) return allFindings;

        Path dir = Paths.get(scriptsDir);
        if (!Files.exists(dir) || !Files.isDirectory(dir)) {
            LOGGER.warn("Scripts directory not found: {}", scriptsDir);
            return allFindings;
        }

        List<Path> scripts = new ArrayList<>();
        try (Stream<Path> files = Files.list(dir)) {
            files.filter(f -> Files.isRegularFile(f) && isSupported(f)).forEach(scripts::add);
        } catch (IOException e) {
            LOGGER.error("Failed to list scripts directory: {}", e.getMessage());
            return allFindings;
        }

        scripts.sort(Path::compareTo);

        for (Path script : scripts) {
            try {
                LOGGER.info("Running user script: {}", script.getFileName());
                List<OwaspTestFinding> findings = executeScript(script);
                allFindings.addAll(findings);
                LOGGER.info("Script {} produced {} finding(s)", script.getFileName(), findings.size());
            } catch (Exception e) {
                LOGGER.error("Script {} failed: {}", script.getFileName(), e.getMessage());
            }
        }

        return allFindings;
    }

    private boolean isSupported(Path file) {
        String name = file.getFileName().toString().toLowerCase();
        return name.endsWith(".py") || name.endsWith(".ts")
            || name.endsWith(".java") || name.endsWith(".kt")
            || name.endsWith(".kts") || name.endsWith(".groovy");
    }

    private List<OwaspTestFinding> executeScript(Path script) throws Exception {
        String name = script.getFileName().toString().toLowerCase();
        Path outputFile = Files.createTempFile("user-script-", ".json");

        List<String> cmd;
        if (name.endsWith(".py")) {
            cmd = List.of("python3", script.toAbsolutePath().toString());
        } else if (name.endsWith(".ts")) {
            cmd = List.of("npx", "tsx", script.toAbsolutePath().toString());
        } else if (name.endsWith(".java")) {
            cmd = List.of("java", script.toAbsolutePath().toString());
        } else if (name.endsWith(".kt")) {
            return runKotlinScript(script, outputFile);
        } else if (name.endsWith(".kts")) {
            cmd = List.of("kotlinc", "-script", script.toAbsolutePath().toString());
        } else if (name.endsWith(".groovy")) {
            cmd = List.of("groovy", script.toAbsolutePath().toString());
        } else {
            throw new IllegalArgumentException("Unsupported script type: " + name);
        }

        List<String> cmdWithArgs = new ArrayList<>(cmd);
        cmdWithArgs.add("--target-url");
        cmdWithArgs.add(targetUrl);
        cmdWithArgs.add("--proxy");
        cmdWithArgs.add(zapProxy);
        cmdWithArgs.add("--output-json");
        cmdWithArgs.add(outputFile.toAbsolutePath().toString());

        runProcess(cmdWithArgs, script.getParent());
        return collectResults(outputFile);
    }

    private List<OwaspTestFinding> runKotlinScript(Path script, Path outputFile) throws Exception {
        Path buildDir = Files.createTempDirectory("kotlin-build-");
        String className = script.getFileName().toString().replace(".kt", "");
        Path jarPath = buildDir.resolve(className + ".jar");

        List<String> compileCmd = List.of(
            "kotlinc", script.toAbsolutePath().toString(),
            "-d", buildDir.toAbsolutePath().toString(),
            "-include-runtime",
            jarPath.toAbsolutePath().toString()
        );
        runProcess(compileCmd, script.getParent());

        List<String> runCmd = new ArrayList<>(List.of("java", "-jar", jarPath.toAbsolutePath().toString()));
        runCmd.add("--target-url");
        runCmd.add(targetUrl);
        runCmd.add("--proxy");
        runCmd.add(zapProxy);
        runCmd.add("--output-json");
        runCmd.add(outputFile.toAbsolutePath().toString());
        runProcess(runCmd, script.getParent());

        return collectResults(outputFile);
    }

    private void runProcess(List<String> cmd, Path workingDir) throws Exception {
        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.directory(workingDir.toFile());
        pb.redirectErrorStream(true);
        long start = System.currentTimeMillis();
        Process process = pb.start();

        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                LOGGER.debug("[{}] {}", workingDir.getFileName(), line);
            }
        }

        int exitCode = process.waitFor();
        long elapsed = System.currentTimeMillis() - start;
        if (exitCode != 0) {
            throw new RuntimeException("Process exited with code " + exitCode + " after " + elapsed + "ms");
        }
    }

    private List<OwaspTestFinding> collectResults(Path outputFile) throws Exception {
        String jsonSource;
        if (Files.exists(outputFile) && Files.size(outputFile) > 0) {
            jsonSource = Files.readString(outputFile, StandardCharsets.UTF_8);
        } else {
            return List.of();
        }
        Files.deleteIfExists(outputFile);

        jsonSource = jsonSource.trim();
        if (jsonSource.isEmpty()) {
            return List.of();
        }
        return parseFindings(jsonSource);
    }

    private List<OwaspTestFinding> parseFindings(String json) {
        List<OwaspTestFinding> findings = new ArrayList<>();
        try {
            if (json.startsWith("[")) {
                JSONArray arr = new JSONArray(json);
                for (int i = 0; i < arr.length(); i++) {
                    JSONObject obj = arr.getJSONObject(i);
                    String url = obj.optString("url", targetUrl);
                    String category = obj.optString("category", "User Script Finding");
                    String description = obj.optString("description", "");
                    String evidence = obj.optString("evidence", "");
                    if (!description.isEmpty()) {
                        findings.add(new OwaspTestFinding(category, description, url, evidence));
                    }
                }
            } else if (json.startsWith("{")) {
                JSONObject obj = new JSONObject(json);
                String url = obj.optString("url", targetUrl);
                String category = obj.optString("category", "User Script Finding");
                String description = obj.optString("description", "");
                String evidence = obj.optString("evidence", "");
                if (!description.isEmpty()) {
                    findings.add(new OwaspTestFinding(category, description, url, evidence));
                }
            }
        } catch (Exception e) {
            LOGGER.warn("Failed to parse script output as JSON: {}", e.getMessage());
        }
        return findings;
    }
}
