package org.zaproxy.addon.playwrightclient.owasp;

import com.microsoft.playwright.Page;
import java.util.*;

public class OwaspA03_Injection_DOMXSS {

    public static List<OwaspTestFinding> test(Page page) {
        List<OwaspTestFinding> findings = new ArrayList<>();

        String html = page.content();

        if (html.contains("<script>alert(") || html.contains("javascript:alert(")) {
            findings.add(new OwaspTestFinding(
                "A03: Injection (DOM XSS)",
                "Possible DOM‑based XSS detected",
                page.url(),
                "Suspicious script tag found"
            ));
        }

        return findings;
    }
}
