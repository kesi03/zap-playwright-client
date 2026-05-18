package org.zaproxy.addon.playwrightclient.owasp;

import com.microsoft.playwright.Page;
import java.util.*;

public class OwaspA04_InsecureDesign {

    public static List<OwaspTestFinding> test(Page page, String baseUrl) {
        List<OwaspTestFinding> findings = new ArrayList<>();

        try {
            page.navigate(baseUrl + "/register");

            // Try a weak password
            page.fill("input[name=password]", "123");
            page.fill("input[name=confirmPassword]", "123");

            page.click("button[type=submit]");

            // If registration succeeds or no error appears
            boolean errorShown = false;
            try {
                errorShown = page.locator(".error, .alert, .validation").isVisible();
            } catch (Exception ignored) {}

            if (!errorShown) {
                findings.add(new OwaspTestFinding(
                    "A04: Insecure Design",
                    "Weak password accepted by registration form",
                    page.url(),
                    "Password '123' was not rejected"
                ));
            }
        } catch (Exception ignored) {}

        return findings;
    }
}
