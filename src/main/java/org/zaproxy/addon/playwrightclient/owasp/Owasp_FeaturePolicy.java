package org.zaproxy.addon.playwrightclient.owasp;

import com.microsoft.playwright.Page;
import java.util.*;

public class Owasp_FeaturePolicy {

    public static List<OwaspTestFinding> test(Page page) {
        List<OwaspTestFinding> findings = new ArrayList<>();

        try {
            page.onResponse(res -> {
                Map<String, String> headers = res.headers();
                if (headers == null || !headers.containsKey("permissions-policy")) {
                    findings.add(new OwaspTestFinding(
                        "A05: Security Misconfiguration",
                        "Missing Permissions-Policy header",
                        res.url(),
                        "permissions-policy missing"
                    ));
                }
            });
        } catch (Exception ignored) {}

        return findings;
    }
}
