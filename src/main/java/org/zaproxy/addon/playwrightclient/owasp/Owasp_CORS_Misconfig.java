package org.zaproxy.addon.playwrightclient.owasp;

import com.microsoft.playwright.Page;
import java.util.*;

public class Owasp_CORS_Misconfig {

    public static List<OwaspTestFinding> test(Page page) {
        List<OwaspTestFinding> findings = new ArrayList<>();

        try {
            page.onResponse(res -> {
                Map<String, String> headers = res.headers();
                String allowOrigin = null;
                if (headers != null) {
                    allowOrigin = headers.get("access-control-allow-origin");
                }

                if ("*".equals(allowOrigin)) {
                    findings.add(new OwaspTestFinding(
                        "A05: Security Misconfiguration",
                        "CORS allows all origins",
                        res.url(),
                        "access-control-allow-origin: *"
                    ));
                }
            });
        } catch (Exception ignored) {}

        return findings;
    }
}
