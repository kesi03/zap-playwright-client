package org.zaproxy.addon.playwrightclient.owasp;

import com.microsoft.playwright.Page;
import java.util.*;

public class OwaspA07_AuthFailures {

    public static List<OwaspTestFinding> test(Page page, String baseUrl) {
        List<OwaspTestFinding> findings = new ArrayList<>();

        page.navigate(baseUrl + "/login");

        if (!page.locator("input[type=password]").isVisible()) {
            findings.add(new OwaspTestFinding(
                "A07: Authentication Failures",
                "Login page missing password field",
                page.url(),
                "Password input not found"
            ));
        }

        return findings;
    }
}
