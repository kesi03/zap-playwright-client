package org.zaproxy.addon.playwrightclient.owasp;

import com.microsoft.playwright.Page;
import java.util.*;

public class Owasp_CSP_NonceReuse {

    public static List<OwaspTestFinding> test(Page page) {
        List<OwaspTestFinding> findings = new ArrayList<>();

        try {
            Object raw = page.evalOnSelectorAll(
                "script[nonce]",
                "els => els.map(e => e.getAttribute('nonce'))"
            );

            List<?> nonces = raw instanceof List ? (List<?>) raw : Collections.emptyList();
            Set<Object> uniq = new HashSet<>(nonces);
            if (uniq.size() < nonces.size()) {
                findings.add(new OwaspTestFinding(
                    "A05: Security Misconfiguration",
                    "CSP nonce reused across scripts",
                    page.url(),
                    nonces.toString()
                ));
            }
        } catch (Exception ignored) {}

        return findings;
    }
}
