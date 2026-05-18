package org.zaproxy.addon.playwrightclient.owasp;

import com.microsoft.playwright.Page;
import java.util.*;

public class Owasp_ThirdPartyWidgets {

    public static List<OwaspTestFinding> test(Page page) {
        List<OwaspTestFinding> findings = new ArrayList<>();

        try {
            Object raw = page.evalOnSelectorAll(
                "script[src]",
                "els => els.map(e => e.src)"
            );

            List<?> scripts = raw instanceof List ? (List<?>) raw : Collections.emptyList();
            for (Object s : scripts) {
                String src = s == null ? "" : s.toString();
                if (src.contains("cdn") && src.startsWith("http://")) {
                    findings.add(new OwaspTestFinding(
                        "A08: Integrity Failures",
                        "Third-party script loaded insecurely",
                        page.url(),
                        src
                    ));
                }
            }
        } catch (Exception ignored) {}

        return findings;
    }
}
