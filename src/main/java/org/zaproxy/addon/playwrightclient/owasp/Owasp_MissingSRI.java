package org.zaproxy.addon.playwrightclient.owasp;

import com.microsoft.playwright.Page;
import java.util.*;

public class Owasp_MissingSRI {

    public static List<OwaspTestFinding> test(Page page) {
        List<OwaspTestFinding> findings = new ArrayList<>();

        try {
            Object raw = page.evaluate(
                "() => Array.from(document.querySelectorAll('script[src]')).map(s => ({ " +
                "  src: s.src, " +
                "  hasIntegrity: !!s.getAttribute('integrity') " +
                "})).filter(s => !s.src.startsWith(window.location.origin) && !s.src.startsWith('/') && !s.src.startsWith('.'))"
            );
            if (!(raw instanceof List)) return findings;

            for (Object item : (List<?>) raw) {
                if (item == null) continue;
                Map<?, ?> script = (Map<?, ?>) item;
                String src = String.valueOf(script.get("src"));
                boolean hasIntegrity = Boolean.TRUE.equals(script.get("hasIntegrity"));

                if (!hasIntegrity) {
                    findings.add(new OwaspTestFinding(
                        "A08: Software & Data Integrity Failures",
                        "External script loaded without SRI integrity attribute",
                        page.url(),
                        "src: " + src
                    ));
                }
            }
        } catch (Exception ignored) {}

        return findings;
    }
}
