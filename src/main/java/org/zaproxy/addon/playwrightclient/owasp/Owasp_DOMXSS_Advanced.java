package org.zaproxy.addon.playwrightclient.owasp;

import com.microsoft.playwright.Page;
import java.util.*;

public class Owasp_DOMXSS_Advanced {

    public static List<OwaspTestFinding> test(Page page) {
        List<OwaspTestFinding> findings = new ArrayList<>();

        try {
            String html = page.content();

            if (html.contains("onerror=") || html.contains("onload=")) {
                findings.add(new OwaspTestFinding(
                    "A03: DOM XSS",
                    "Inline event handler detected (possible XSS vector)",
                    page.url(),
                    "Found onerror/onload attribute"
                ));
            }
        } catch (Exception ignored) {}

        return findings;
    }
}
