package org.zaproxy.addon.playwrightclient.owasp;

import com.microsoft.playwright.Page;
import java.util.*;

public class Owasp_AutocompleteSensitive {

    public static List<OwaspTestFinding> test(Page page) {
        List<OwaspTestFinding> findings = new ArrayList<>();

        try {
            Object raw = page.evalOnSelectorAll(
                "input[type=password], input[name*=credit], input[name*=card]",
                "els => els.map(e => e.getAttribute('autocomplete'))"
            );

            List<?> fields = raw instanceof List ? (List<?>) raw : Collections.emptyList();
            for (Object acObj : fields) {
                String ac = acObj == null ? null : acObj.toString();
                if (ac == null || "on".equalsIgnoreCase(ac)) {
                    findings.add(new OwaspTestFinding(
                        "A02: Sensitive Data Exposure",
                        "Sensitive input field has autocomplete enabled",
                        page.url(),
                        "autocomplete=" + ac
                    ));
                }
            }
        } catch (Exception ignored) {}

        return findings;
    }
}
