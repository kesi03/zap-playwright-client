package org.zaproxy.addon.playwrightclient.owasp;

import com.microsoft.playwright.Page;
import java.util.*;

public class Owasp_UnsafeHTTPMethods {

    public static List<OwaspTestFinding> test(Page page) {
        List<OwaspTestFinding> findings = new ArrayList<>();

        try {
            page.onRequest(request -> {
                String method = request.method().toUpperCase();
                if ("DELETE".equals(method) || "PUT".equals(method) || "PATCH".equals(method)) {
                    findings.add(new OwaspTestFinding(
                        "A01: Broken Access Control",
                        "Unsafe HTTP method detected — verify authorization checks",
                        request.url(),
                        "Method: " + method
                    ));
                }
            });
        } catch (Exception ignored) {}

        return findings;
    }
}
