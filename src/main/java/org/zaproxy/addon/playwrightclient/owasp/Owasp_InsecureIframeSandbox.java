package org.zaproxy.addon.playwrightclient.owasp;

import com.microsoft.playwright.Page;
import java.util.*;

public class Owasp_InsecureIframeSandbox {

    public static List<OwaspTestFinding> test(Page page) {
        List<OwaspTestFinding> findings = new ArrayList<>();

        try {
            Object raw = page.evalOnSelectorAll("iframe[sandbox]", "els => els.map(e => e.getAttribute('sandbox'))");
            List<?> attrs = raw instanceof List ? (List<?>) raw : Collections.emptyList();
            for (Object a : attrs) {
                String s = a == null ? "" : a.toString();
                if (s.contains("allow-same-origin") || s.contains("allow-scripts")) {
                    findings.add(new OwaspTestFinding(
                        "A05: Security Misconfiguration",
                        "Iframe sandbox allows risky permissions",
                        page.url(),
                        "sandbox=" + s
                    ));
                }
            }
        } catch (Exception ignored) {}

        return findings;
    }
}
