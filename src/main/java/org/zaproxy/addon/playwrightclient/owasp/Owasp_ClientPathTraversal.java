package org.zaproxy.addon.playwrightclient.owasp;

import com.microsoft.playwright.Page;
import java.util.*;

public class Owasp_ClientPathTraversal {

    public static List<OwaspTestFinding> test(Page page, String baseUrl) {
        List<OwaspTestFinding> findings = new ArrayList<>();

        try {
            String payload = "../etc/passwd";
            page.navigate(baseUrl + "/static/" + payload);
            String content = page.content();
            if (content != null && (content.contains("root:") || content.contains("/bin/"))) {
                findings.add(new OwaspTestFinding(
                    "A03: Injection (Path Traversal)",
                    "Client-side indicates possible path traversal exposure",
                    page.url(),
                    payload
                ));
            }
        } catch (Exception ignored) {}

        return findings;
    }
}
