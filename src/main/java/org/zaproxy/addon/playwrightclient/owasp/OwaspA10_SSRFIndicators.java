package org.zaproxy.addon.playwrightclient.owasp;

import com.microsoft.playwright.Page;
import java.util.*;

public class OwaspA10_SSRFIndicators {

    public static List<OwaspTestFinding> test(Page page) {
        List<OwaspTestFinding> findings = new ArrayList<>();

        try {
            page.onRequest(req -> {
                String url = req.url();

                if (url.contains("169.254.") || url.toLowerCase().contains("metadata") || url.contains("localhost")) {
                    findings.add(new OwaspTestFinding(
                        "A10: SSRF Indicators",
                        "Client-side code attempted to access internal metadata or localhost",
                        page.url(),
                        url
                    ));
                }
            });
        } catch (Exception ignored) {}

        return findings;
    }
}
