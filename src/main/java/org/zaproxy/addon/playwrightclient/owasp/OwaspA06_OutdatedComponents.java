package org.zaproxy.addon.playwrightclient.owasp;

import com.microsoft.playwright.Page;
import java.util.*;

public class OwaspA06_OutdatedComponents {

    public static List<OwaspTestFinding> test(Page page) {
        List<OwaspTestFinding> findings = new ArrayList<>();

        try {
            // Check for React devtools hook (only present in dev builds)
            Object devtools = page.evaluate("() => !!window.__REACT_DEVTOOLS_GLOBAL_HOOK__");
            boolean reactDevTools = devtools instanceof Boolean ? (Boolean) devtools : false;

            if (reactDevTools) {
                findings.add(new OwaspTestFinding(
                    "A06: Vulnerable & Outdated Components",
                    "React DevTools detected in production",
                    page.url(),
                    "window.__REACT_DEVTOOLS_GLOBAL_HOOK__ present"
                ));
            }

            // Check for React version leaks
            Object versionObj = page.evaluate("() => window.React?.version || null");
            if (versionObj != null) {
                String reactVersion = versionObj.toString();
                findings.add(new OwaspTestFinding(
                    "A06: Vulnerable & Outdated Components",
                    "React version exposed to client",
                    page.url(),
                    "React version: " + reactVersion
                ));
            }
        } catch (Exception ignored) {}

        return findings;
    }
}
