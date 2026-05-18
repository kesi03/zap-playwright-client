package org.zaproxy.addon.playwrightclient.owasp;

import com.microsoft.playwright.Page;
import java.util.*;

public class OwaspA01_BrokenAccessControl {

    public static List<OwaspTestFinding> test(Page page, String baseUrl) {
        List<OwaspTestFinding> findings = new ArrayList<>();

        String[] sensitivePaths = {
            "/admin", "/settings", "/internal", "/manage", "/api/admin"
        };

        for (String path : sensitivePaths) {
            try {
                page.navigate(baseUrl + path);

                if (!page.url().contains("login") && !page.url().contains("unauthorized")) {
                    findings.add(new OwaspTestFinding(
                        "A01: Broken Access Control",
                        "Sensitive page accessible without authentication",
                        page.url(),
                        "Visited: " + path
                    ));
                }
            } catch (Exception ignored) {}
        }

        return findings;
    }
}
