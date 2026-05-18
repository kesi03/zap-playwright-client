package org.zaproxy.addon.playwrightclient.owasp;

import com.microsoft.playwright.Page;
import java.util.*;

public class Owasp_ReflectedParams {

    public static List<OwaspTestFinding> test(Page page, String baseUrl) {
        List<OwaspTestFinding> findings = new ArrayList<>();

        try {
            String payload = "playwright_xss_test";
            page.navigate(baseUrl + "?q=" + payload);
            String content = page.content();
            if (content != null && content.contains(payload)) {
                findings.add(new OwaspTestFinding(
                    "A03: Injection (Reflected XSS)",
                    "User-controlled parameter reflected in DOM",
                    page.url(),
                    "Parameter q reflected"
                ));
            }
        } catch (Exception ignored) {}

        return findings;
    }
}
