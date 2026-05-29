package org.zaproxy.addon.playwrightclient.owasp;

import com.microsoft.playwright.Page;
import java.util.*;

public class Owasp_innerHTML_XSS {

    public static List<OwaspTestFinding> test(Page page) {
        List<OwaspTestFinding> findings = new ArrayList<>();

        try {
            String content = page.content();
            if (content == null) return findings;

            if (content.contains(".innerHTML") && content.matches("(?s).*\\.innerHTML\\s*=.*")) {
                findings.add(new OwaspTestFinding(
                    "A03: Injection",
                    "innerHTML assignment detected — possible DOM XSS vector",
                    page.url(),
                    "element.innerHTML = ... pattern found"
                ));
            }

            if (content.contains("document.write(") || content.contains("document.writeln(")) {
                findings.add(new OwaspTestFinding(
                    "A03: Injection",
                    "document.write() usage detected — possible DOM XSS vector",
                    page.url(),
                    "document.write() pattern found"
                ));
            }
        } catch (Exception ignored) {}

        return findings;
    }
}
