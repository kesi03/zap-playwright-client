///usr/bin/env java --source 21
import com.microsoft.playwright.*;
import com.microsoft.playwright.options.Proxy;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

public class CheckBrowserSecurity {
    record Finding(String url, String category, String description, String evidence) {}

    public static void main(String[] args) throws Exception {
        String targetUrl = "";
        String proxyAddr = "";
        String outputJson = "";
        for (int i = 0; i < args.length; i += 2) {
            switch (args[i]) {
                case "--target-url" -> targetUrl = args[i + 1];
                case "--proxy" -> proxyAddr = args[i + 1];
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

        try (Playwright pw = Playwright.create()) {
            BrowserType.LaunchOptions opts = new BrowserType.LaunchOptions()
                .setHeadless(true);
            if (!proxyAddr.isEmpty()) {
                opts.setProxy(new Proxy(proxyAddr));
            }

            Browser browser = pw.chromium().launch(opts);
            try {
                BrowserContext context = browser.newContext(new Browser.NewContextOptions()
                    .setIgnoreHTTPSErrors(true)
                    .setUserAgent("Mozilla/5.0 (compatible; ZAP-Playwright-UserScript/1.0)"));
                Page page = context.newPage();

                page.onConsoleMessage(msg -> {
                    // collected inline
                });

                try {
                    page.navigate(targetUrl, new Page.NavigateOptions()
                        .setWaitUntil(Page.WaitUntilState.NETWORKIDLE));

                    // Password field autocomplete check
                    List<ElementHandle> passwordInputs = page.querySelectorAll("input[type='password']");
                    for (ElementHandle inp : passwordInputs) {
                        String autocomplete = inp.getAttribute("autocomplete");
                        if (autocomplete == null || autocomplete.equals("on")) {
                            String formId = (String) inp.evaluate(
                                "el -> (el.closest('form') || {}).id || el.name || 'unnamed'");
                            findings.add(new Finding(targetUrl, "Autocomplete Sensitive",
                                "Password field '" + formId + "' has autocomplete=" + autocomplete
                                    + " — credentials may be cached",
                                "<input type=password name=" + formId + " autocomplete=" + autocomplete + ">"));
                        }
                    }

                    // GET method forms with password fields
                    List<ElementHandle> forms = page.querySelectorAll("form");
                    for (ElementHandle form : forms) {
                        String methodAttr = form.getAttribute("method");
                        String method = methodAttr != null ? methodAttr.toUpperCase() : "GET";
                        if (method.equals("GET") && !form.querySelectorAll("input[type='password']").isEmpty()) {
                            String action = form.getAttribute("action");
                            if (action == null) action = "(self)";
                            findings.add(new Finding(targetUrl, "Insecure Design",
                                "Form with password field uses GET method — credentials exposed in URL",
                                "<form method=GET action=" + action + "> with password field"));
                        }
                    }

                    // Insecure form action URLs
                    for (ElementHandle form : forms) {
                        String action = form.getAttribute("action");
                        if (action != null && action.startsWith("http://")) {
                            findings.add(new Finding(targetUrl, "Login Over HTTP",
                                "Form submits credentials over unencrypted HTTP: " + action,
                                "<form action=" + action + ">"));
                        }
                    }

                } catch (Exception e) {
                    findings.add(new Finding(targetUrl, "User Script Finding",
                        "Playwright navigation failed: " + e.getMessage(), e.toString()));
                }

            } finally {
                browser.close();
            }
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
