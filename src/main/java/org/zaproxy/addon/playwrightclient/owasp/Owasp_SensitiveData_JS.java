package org.zaproxy.addon.playwrightclient.owasp;

import com.microsoft.playwright.Page;
import java.util.*;

public class Owasp_SensitiveData_JS {

    public static List<OwaspTestFinding> test(Page page) {
        List<OwaspTestFinding> findings = new ArrayList<>();

        try {
            String js = page.content();

            if (js.contains("apiKey") || js.contains("secret") || js.contains("token")) {
                findings.add(new OwaspTestFinding(
                    "A02: Sensitive Data Exposure",
                    "Sensitive keywords found in client-side JS",
                    page.url(),
                    "Found apiKey/secret/token"
                ));
            }
        } catch (Exception ignored) {}

        return findings;
    }
}
