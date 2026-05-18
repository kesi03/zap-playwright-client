package org.zaproxy.addon.playwrightclient.owasp;

import com.microsoft.playwright.Page;
import java.util.*;

public class Owasp_OAuth_ImplicitFlow {

    public static List<OwaspTestFinding> test(Page page) {
        List<OwaspTestFinding> findings = new ArrayList<>();

        try {
            String url = page.url();

            if (url != null && url.contains("access_token=") && url.contains("#")) {
                findings.add(new OwaspTestFinding(
                    "A07: Authentication Failures",
                    "OAuth implicit flow detected (tokens in URL fragment)",
                    url,
                    "access_token in URL"
                ));
            }
        } catch (Exception ignored) {}

        return findings;
    }
}
