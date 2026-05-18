package org.zaproxy.addon.playwrightclient.owasp;

import com.microsoft.playwright.Page;
import java.util.*;

public class Owasp_ReactHydrationErrors {

    public static List<OwaspTestFinding> test(Page page) {
        List<OwaspTestFinding> findings = new ArrayList<>();

        try {
            page.onConsoleMessage(msg -> {
                if (msg.text() != null && msg.text().toLowerCase().contains("hydration")) {
                    findings.add(new OwaspTestFinding(
                        "A06: Vulnerable & Outdated Components",
                        "React hydration error detected in console",
                        page.url(),
                        msg.text()
                    ));
                }
            });
        } catch (Exception ignored) {}

        return findings;
    }
}
