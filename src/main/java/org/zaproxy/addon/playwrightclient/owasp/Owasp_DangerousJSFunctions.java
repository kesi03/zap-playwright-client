package org.zaproxy.addon.playwrightclient.owasp;

import com.microsoft.playwright.Page;
import java.util.*;

public class Owasp_DangerousJSFunctions {

    public static List<OwaspTestFinding> test(Page page) {
        List<OwaspTestFinding> findings = new ArrayList<>();

        try {
            String js = page.content();
            if (js.contains("eval(") || js.contains("new Function(")) {
                findings.add(new OwaspTestFinding(
                    "A03: Injection",
                    "Dangerous JavaScript functions detected",
                    page.url(),
                    "eval or new Function used"
                ));
            }
        } catch (Exception ignored) {}

        return findings;
    }
}
