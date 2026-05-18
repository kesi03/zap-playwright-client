package org.zaproxy.addon.playwrightclient.owasp;

import com.microsoft.playwright.Page;
import java.util.*;

public class OwaspA09_LoggingMonitoring {

    public static List<OwaspTestFinding> test(Page page) {
        List<OwaspTestFinding> findings = new ArrayList<>();

        page.onConsoleMessage(msg -> {
            if (msg.type().equals("error")) {
                findings.add(new OwaspTestFinding(
                    "A09: Logging & Monitoring Failures",
                    "JavaScript error detected",
                    page.url(),
                    msg.text()
                ));
            }
        });

        return findings;
    }
}
