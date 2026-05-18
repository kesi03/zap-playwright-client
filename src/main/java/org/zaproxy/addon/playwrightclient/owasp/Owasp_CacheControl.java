package org.zaproxy.addon.playwrightclient.owasp;

import com.microsoft.playwright.Page;
import java.util.*;

public class Owasp_CacheControl {

    public static List<OwaspTestFinding> test(Page page) {
        List<OwaspTestFinding> findings = new ArrayList<>();

        try {
            page.onResponse(res -> {
                Map<String, String> headers = res.headers();
                if (headers == null || !headers.containsKey("cache-control")) {
                    findings.add(new OwaspTestFinding(
                        "A05: Security Misconfiguration",
                        "Missing Cache-Control header",
                        res.url(),
                        "cache-control missing"
                    ));
                }
            });
        } catch (Exception ignored) {}

        return findings;
    }
}
