package org.zaproxy.addon.playwrightclient.owasp;

import com.microsoft.playwright.Page;
import java.util.*;

public class Owasp_MixedContent {

    public static List<OwaspTestFinding> test(Page page) {
        List<OwaspTestFinding> findings = new ArrayList<>();

        try {
            Object raw = page.evalOnSelectorAll(
                "*[src], *[href]",
                "els => els.map(e => e.src || e.href)"
            );

            List<?> resources = raw instanceof List ? (List<?>) raw : Collections.emptyList();

            for (Object rObj : resources) {
                if (rObj == null) continue;
                String r = rObj.toString();
                if (r.startsWith("http://") && page.url().startsWith("https://")) {
                    findings.add(new OwaspTestFinding(
                        "A02: Cryptographic Failures",
                        "Mixed content detected",
                        page.url(),
                        r
                    ));
                }
            }
        } catch (Exception ignored) {}

        return findings;
    }
}
