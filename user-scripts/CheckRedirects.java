///usr/bin/env jbang
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

public class CheckRedirects {
    record Finding(String url, String category, String description, String evidence) {}

    public static void main(String[] args) throws Exception {
        String targetUrl = "";
        String outputJson = "";
        for (int i = 0; i < args.length; i += 2) {
            switch (args[i]) {
                case "--target-url" -> targetUrl = args[i + 1];
                case "--output-json" -> outputJson = args[i + 1];
            }
        }

        List<Finding> findings = new ArrayList<>();

        if (targetUrl.isEmpty()) {
            findings.add(new Finding("", "User Script Finding",
                "Missing --target-url argument", "target-url is required"));
            writeOutput(findings, outputJson);
            return;
        }

        HttpClient client = HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.NEVER)
            .connectTimeout(java.time.Duration.ofSeconds(10))
            .build();

        try {
            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(targetUrl))
                .GET()
                .build();

            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            int status = response.statusCode();

            if (status >= 300 && status < 400) {
                String location = response.headers().firstValue("location").orElse("(none)");
                findings.add(new Finding(targetUrl, "Open Redirect",
                    "Server returns redirect (" + status + ") to: " + location,
                    "Location: " + location));

                if (location.contains("://")) {
                    findings.add(new Finding(targetUrl, "Security Misconfiguration",
                        "Redirect targets external URL: " + location,
                        "Cross-origin redirect to " + location));
                }
            }

            String server = response.headers().firstValue("server").orElse("");
            if (!server.isEmpty()) {
                findings.add(new Finding(targetUrl, "Information Disclosure",
                    "Server header exposes: " + server,
                    "Server: " + server));
            }

        } catch (Exception e) {
            findings.add(new Finding(targetUrl, "User Script Finding",
                "Request failed: " + e.getMessage(), e.toString()));
        }

        writeOutput(findings, outputJson);
    }

    static void writeOutput(List<Finding> findings, String path) throws Exception {
        StringBuilder json = new StringBuilder("[\n");
        for (int i = 0; i < findings.size(); i++) {
            Finding f = findings.get(i);
            json.append("  {")
                .append("\"url\":\"").append(escape(f.url)).append("\",")
                .append("\"category\":\"").append(escape(f.category)).append("\",")
                .append("\"description\":\"").append(escape(f.description)).append("\",")
                .append("\"evidence\":\"").append(escape(f.evidence)).append("\"")
                .append("}");
            if (i < findings.size() - 1) json.append(",");
            json.append("\n");
        }
        json.append("]");

        String output = json.toString();
        if (!path.isEmpty()) {
            Files.writeString(Paths.get(path), output);
        } else {
            System.out.println(output);
        }
    }

    static String escape(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"")
                .replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t");
    }
}
