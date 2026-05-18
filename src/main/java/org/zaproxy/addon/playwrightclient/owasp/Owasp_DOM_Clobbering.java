package org.zaproxy.addon.playwrightclient.owasp;

import com.microsoft.playwright.Page;
import java.util.*;

public class Owasp_DOM_Clobbering {

    public static List<OwaspTestFinding> test(Page page) {
        List<OwaspTestFinding> findings = new ArrayList<>();

        try {
            // Check for common clobbering names
            String[] names = {"constructor","__proto__","prototype","toString"};
            String html = page.content();
            for (String n : names) {
                if (html.contains("window[\""+n+"\"]") || html.contains("document[\""+n+"\"]")) {
                    findings.add(new OwaspTestFinding(
                        "A03: Injection (DOM Clobbering)",
                        "Potential DOM clobbering vector detected",
                        page.url(),
                        "Found usage of " + n
                    ));
                }
            }
        } catch (Exception ignored) {}

        return findings;
    }
}
