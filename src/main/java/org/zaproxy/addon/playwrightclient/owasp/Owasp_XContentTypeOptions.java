package org.zaproxy.addon.playwrightclient.owasp;

import com.microsoft.playwright.Page;
import java.util.*;

public class Owasp_XContentTypeOptions {

    public static List<OwaspTestFinding> test(Page page) {
        List<OwaspTestFinding> findings = new ArrayList<>();

        try {
            page.onResponse(res -> {
                Map<String, String> headers = res.headers();
                boolean hasNosniff = false;
                if (headers != null) {
                    for (Map.Entry<String, String> h : headers.entrySet()) {
                        if (h.getKey().equalsIgnoreCase("x-content-type-options")) {
                            hasNosniff = true;
                            break;
                        }
                    }
                }
                if (!hasNosniff) {
                    findings.add(new OwaspTestFinding(
                        "A05: Security Misconfiguration",
                        "Missing X-Content-Type-Options header",
                        res.url(),
                        "X-Content-Type-Options: nosniff not set"
                    ));
                }
            });
        } catch (Exception ignored) {}

        return findings;
    }
}
