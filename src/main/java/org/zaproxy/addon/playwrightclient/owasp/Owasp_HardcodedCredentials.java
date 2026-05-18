package org.zaproxy.addon.playwrightclient.owasp;

import com.microsoft.playwright.Page;
import java.util.*;

public class Owasp_HardcodedCredentials {

    public static List<OwaspTestFinding> test(Page page) {
        List<OwaspTestFinding> findings = new ArrayList<>();

        try {
            String js = page.content();
            if (js.matches("(?s).*?(password|secret|apikey|token)\\s*[:=]\\s*['\"][^'\"]+['\"].*")) {
                findings.add(new OwaspTestFinding(
                    "A02: Sensitive Data Exposure",
                    "Hardcoded credentials found in client-side JS",
                    page.url(),
                    "Detected password/secret/apiKey/token assignment"
                ));
            }
        } catch (Exception ignored) {}

        return findings;
    }
}
