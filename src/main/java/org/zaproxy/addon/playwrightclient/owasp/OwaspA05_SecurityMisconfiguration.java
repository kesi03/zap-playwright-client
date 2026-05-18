package org.zaproxy.addon.playwrightclient.owasp;

import com.microsoft.playwright.Page;
import java.util.*;

public class OwaspA05_SecurityMisconfiguration {

    public static List<OwaspTestFinding> test(Page page) {
        List<OwaspTestFinding> findings = new ArrayList<>();

        page.onResponse(res -> {
            Map<String, String> headers = res.headers();

            if (!headers.containsKey("content-security-policy")) {
                findings.add(new OwaspTestFinding(
                    "A05: Security Misconfiguration",
                    "Missing Content-Security-Policy header",
                    res.url(),
                    "CSP header not present"
                ));
            }

            if (!headers.containsKey("x-frame-options")) {
                findings.add(new OwaspTestFinding(
                    "A05: Security Misconfiguration",
                    "Missing X-Frame-Options header",
                    res.url(),
                    "XFO header not present"
                ));
            }
        });

        return findings;
    }
}
