package org.zaproxy.addon.playwrightclient.owasp;

import com.microsoft.playwright.Page;
import java.util.*;

public class Owasp_ServiceWorker {

    public static List<OwaspTestFinding> test(Page page) {
        List<OwaspTestFinding> findings = new ArrayList<>();

        try {
            Object hasSW = page.evaluate("() => !!navigator.serviceWorker.controller");
            boolean present = hasSW instanceof Boolean ? (Boolean) hasSW : false;
            if (present) {
                findings.add(new OwaspTestFinding(
                    "A08: Integrity Failures",
                    "Service Worker active — check for caching of sensitive data",
                    page.url(),
                    "navigator.serviceWorker.controller present"
                ));
            }
        } catch (Exception ignored) {}

        return findings;
    }
}
