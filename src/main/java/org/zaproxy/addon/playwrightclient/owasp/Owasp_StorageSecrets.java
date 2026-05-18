package org.zaproxy.addon.playwrightclient.owasp;

import com.microsoft.playwright.Page;
import java.util.*;

public class Owasp_StorageSecrets {

    public static List<OwaspTestFinding> test(Page page) {
        List<OwaspTestFinding> findings = new ArrayList<>();

        try {
            Object ls = page.evaluate("() => JSON.stringify(localStorage)");
            Object ss = page.evaluate("() => JSON.stringify(sessionStorage)");
            String lss = ls == null ? "" : ls.toString();
            String sss = ss == null ? "" : ss.toString();

            if (lss.contains("token") || lss.contains("secret") || lss.contains("apiKey")) {
                findings.add(new OwaspTestFinding(
                    "A02: Sensitive Data Exposure",
                    "Sensitive data stored in localStorage",
                    page.url(),
                    lss
                ));
            }

            if (sss.contains("token") || sss.contains("secret") || sss.contains("apiKey")) {
                findings.add(new OwaspTestFinding(
                    "A02: Sensitive Data Exposure",
                    "Sensitive data stored in sessionStorage",
                    page.url(),
                    sss
                ));
            }
        } catch (Exception ignored) {}

        return findings;
    }
}
