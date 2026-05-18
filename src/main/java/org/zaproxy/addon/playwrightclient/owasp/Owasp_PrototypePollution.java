package org.zaproxy.addon.playwrightclient.owasp;

import com.microsoft.playwright.Page;
import java.util.*;

public class Owasp_PrototypePollution {

    public static List<OwaspTestFinding> test(Page page) {
        List<OwaspTestFinding> findings = new ArrayList<>();

        try {
            String content = page.content();
            // heuristic: look for '__proto__' usage
            if (content.contains("__proto__") || content.contains("prototypePollution")) {
                findings.add(new OwaspTestFinding(
                    "A03: Injection (Prototype Pollution)",
                    "Potential prototype pollution indicators in client JS",
                    page.url(),
                    "__proto__ usage found"
                ));
            }
        } catch (Exception ignored) {}

        return findings;
    }
}
