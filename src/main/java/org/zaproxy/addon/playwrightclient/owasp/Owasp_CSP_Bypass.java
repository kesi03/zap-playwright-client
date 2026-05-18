package org.zaproxy.addon.playwrightclient.owasp;

import com.microsoft.playwright.Page;
import java.util.*;

public class Owasp_CSP_Bypass {

    public static List<OwaspTestFinding> test(Page page) {
        List<OwaspTestFinding> findings = new ArrayList<>();

        try {
            Object cspObj = page.evaluate("() => document.querySelector('meta[http-equiv=\"Content-Security-Policy\"]')?.content || ''");
            String csp = cspObj == null ? "" : cspObj.toString();

            if (csp.isEmpty() || csp.contains("unsafe-inline") || csp.contains("unsafe-eval")) {
                findings.add(new OwaspTestFinding(
                    "A05: Security Misconfiguration",
                    "CSP allows unsafe inline or eval",
                    page.url(),
                    csp
                ));
            }
        } catch (Exception ignored) {}

        return findings;
    }
}
