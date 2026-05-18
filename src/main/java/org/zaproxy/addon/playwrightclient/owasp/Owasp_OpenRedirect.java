package org.zaproxy.addon.playwrightclient.owasp;

import com.microsoft.playwright.Page;
import java.util.*;

public class Owasp_OpenRedirect {

    public static List<OwaspTestFinding> test(Page page, String baseUrl) {
        List<OwaspTestFinding> findings = new ArrayList<>();

        String[] redirectParams = {"redirect", "next", "url", "returnUrl"};

        try {
            for (String param : redirectParams) {
                String testUrl = baseUrl + "/login?" + param + "=https://evil.com";

                page.navigate(testUrl);

                if (page.url().contains("evil.com")) {
                    findings.add(new OwaspTestFinding(
                        "A01: Broken Access Control",
                        "Open redirect vulnerability",
                        testUrl,
                        "Redirected to external domain"
                    ));
                }
            }
        } catch (Exception ignored) {}

        return findings;
    }
}
