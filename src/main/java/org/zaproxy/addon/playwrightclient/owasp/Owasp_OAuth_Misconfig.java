package org.zaproxy.addon.playwrightclient.owasp;

import com.microsoft.playwright.Page;
import java.util.*;

public class Owasp_OAuth_Misconfig {

    public static List<OwaspTestFinding> test(Page page) {
        List<OwaspTestFinding> findings = new ArrayList<>();

        try {
            String content = page.content();
            if (content.contains("oauth" ) && (content.contains("client_secret") || content.contains("clientId"))) {
                findings.add(new OwaspTestFinding(
                    "A06: Vulnerable & Outdated Components",
                    "OAuth client secrets or IDs found in client-side code",
                    page.url(),
                    "oauth artifacts in JS"
                ));
            }
        } catch (Exception ignored) {}

        return findings;
    }
}
