package org.zaproxy.addon.playwrightclient.owasp;

import com.microsoft.playwright.Page;
import java.util.*;

public class Owasp_SPA_RouteEnumeration {

    public static List<OwaspTestFinding> test(Page page) {
        List<OwaspTestFinding> findings = new ArrayList<>();

        try {
            Object raw = page.evaluate("() => (window.__ROUTES__ || null)");
            if (raw != null) {
                findings.add(new OwaspTestFinding(
                    "A04: Insecure Design",
                    "SPA route enumeration data found on window",
                    page.url(),
                    String.valueOf(raw)
                ));
            }
        } catch (Exception ignored) {}

        return findings;
    }
}
