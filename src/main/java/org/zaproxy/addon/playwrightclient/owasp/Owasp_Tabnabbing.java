package org.zaproxy.addon.playwrightclient.owasp;

import com.microsoft.playwright.Page;
import java.util.*;

public class Owasp_Tabnabbing {

    public static List<OwaspTestFinding> test(Page page) {
        List<OwaspTestFinding> findings = new ArrayList<>();

        try {
            Object raw = page.evalOnSelectorAll(
                "a[target='_blank']",
                "els => els.map(e => ({ href: e.href, rel: e.rel }))"
            );
            if (!(raw instanceof List)) return findings;

            for (Object item : (List<?>) raw) {
                if (item == null) continue;
                String href = String.valueOf(((Map<?, ?>) item).get("href"));
                String rel = String.valueOf(((Map<?, ?>) item).get("rel"));
                if (!rel.contains("noopener") && !rel.contains("noreferrer")) {
                    findings.add(new OwaspTestFinding(
                        "A01: Broken Access Control",
                        "Tabnabbing — target=_blank link missing rel=noopener noreferrer",
                        href,
                        "rel=\"" + rel + "\""
                    ));
                }
            }
        } catch (Exception ignored) {}

        return findings;
    }
}
