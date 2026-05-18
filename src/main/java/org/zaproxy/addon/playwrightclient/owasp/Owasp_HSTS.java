package org.zaproxy.addon.playwrightclient.owasp;

import com.microsoft.playwright.Page;
import java.util.*;

public class Owasp_HSTS {

    public static List<OwaspTestFinding> test(Page page) {
        List<OwaspTestFinding> findings = new ArrayList<>();

        try {
            page.onResponse(res -> {
                Map<String, String> headers = res.headers();
                if (headers == null || !headers.containsKey("strict-transport-security")) {
                    findings.add(new OwaspTestFinding(
                        "A02: Cryptographic Failures",
                        "Missing HSTS header",
                        res.url(),
                        "strict-transport-security missing"
                    ));
                }
            });
        } catch (Exception ignored) {}

        return findings;
    }
}
