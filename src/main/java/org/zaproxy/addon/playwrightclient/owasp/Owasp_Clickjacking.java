package org.zaproxy.addon.playwrightclient.owasp;

import com.microsoft.playwright.Page;
import java.util.*;

public class Owasp_Clickjacking {

    public static List<OwaspTestFinding> test(Page page) {
        List<OwaspTestFinding> findings = new ArrayList<>();

        try {
            Object xfoObj = page.evaluate("() => document.querySelector('meta[http-equiv=\\\"X-Frame-Options\\\"]')?.content || ''");
            String xfo = xfoObj == null ? "" : xfoObj.toString();

            Object ca = page.evaluate("() => (document.querySelector('meta[http-equiv=\\\"Content-Security-Policy\\\"]')?.content || '')");
            String csp = ca == null ? "" : ca.toString();

            if (xfo.isEmpty() && !csp.contains("frame-ancestors")) {
                findings.add(new OwaspTestFinding(
                    "A05: Security Misconfiguration",
                    "Page does not prevent clickjacking",
                    page.url(),
                    "Missing X-Frame-Options or CSP frame-ancestors"
                ));
            }
        } catch (Exception ignored) {}

        return findings;
    }
}
