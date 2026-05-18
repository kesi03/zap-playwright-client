package org.zaproxy.addon.playwrightclient.owasp;

import com.microsoft.playwright.Page;
import java.util.*;

public class Owasp_EnvLeak {

    public static List<OwaspTestFinding> test(Page page) {
        List<OwaspTestFinding> findings = new ArrayList<>();

        try {
            String js = page.content();
            if (js.contains("process.env")) {
                findings.add(new OwaspTestFinding(
                    "A02: Sensitive Data Exposure",
                    "Environment variables exposed to client",
                    page.url(),
                    "process.env found"
                ));
            }
        } catch (Exception ignored) {}

        return findings;
    }
}
