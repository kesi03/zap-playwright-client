package org.zaproxy.addon.playwrightclient.owasp;

import com.microsoft.playwright.Page;
import java.util.*;

public class OwaspA08_IntegrityFailures {

    public static List<OwaspTestFinding> test(Page page) {
        List<OwaspTestFinding> findings = new ArrayList<>();

        Object raw = page.evalOnSelectorAll(
            "script[src]",
            "els => els.map(e => e.src)"
        );

        List<?> scripts = raw instanceof List ? (List<?>) raw : Collections.emptyList();

        for (Object srcObj : scripts) {
            String src = srcObj == null ? "" : srcObj.toString();
            if (src.startsWith("http://")) {
                findings.add(new OwaspTestFinding(
                    "A08: Integrity Failures",
                    "Script loaded over insecure HTTP",
                    page.url(),
                    src
                ));
            }
        }

        return findings;
    }
}
