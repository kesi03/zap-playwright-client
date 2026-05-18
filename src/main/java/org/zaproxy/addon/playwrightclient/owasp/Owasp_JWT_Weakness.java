package org.zaproxy.addon.playwrightclient.owasp;

import com.microsoft.playwright.Page;
import java.util.*;

public class Owasp_JWT_Weakness {

    public static List<OwaspTestFinding> test(Page page) {
        List<OwaspTestFinding> findings = new ArrayList<>();

        try {
            String js = page.content();
            if (js.contains("jwt.decode") || js.contains("atob(")) {
                findings.add(new OwaspTestFinding(
                    "A02: Sensitive Data Exposure",
                    "Client-side JWT decoding detected",
                    page.url(),
                    "jwt.decode or atob used"
                ));
            }
        } catch (Exception ignored) {}

        return findings;
    }
}
