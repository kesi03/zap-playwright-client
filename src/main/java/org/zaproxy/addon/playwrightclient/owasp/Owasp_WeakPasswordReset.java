package org.zaproxy.addon.playwrightclient.owasp;

import com.microsoft.playwright.Page;
import java.util.*;

public class Owasp_WeakPasswordReset {

    public static List<OwaspTestFinding> test(Page page, String baseUrl) {
        List<OwaspTestFinding> findings = new ArrayList<>();

        try {
            page.navigate(baseUrl + "/forgot-password");
            // check for reset by GET (token in URL) or weak flows
            if (page.content().contains("reset_token") || page.url().contains("token=")) {
                findings.add(new OwaspTestFinding(
                    "A04: Insecure Design",
                    "Password reset token exposed in page or URL",
                    page.url(),
                    "reset token present"
                ));
            }
        } catch (Exception ignored) {}

        return findings;
    }
}
