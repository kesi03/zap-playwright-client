package org.zaproxy.addon.playwrightclient.owasp;

import com.microsoft.playwright.Page;
import java.util.*;

public class Owasp_FileUpload_Insecure {

    public static List<OwaspTestFinding> test(Page page) {
        List<OwaspTestFinding> findings = new ArrayList<>();

try {
            Object raw = page.evalOnSelectorAll("input[type=file]", "els => els.map(e => e.getAttribute('accept'))");
            List<?> acceptsList = raw instanceof List ? (List<?>) raw : Collections.emptyList();
            for (Object a : acceptsList) {
                String s = a == null ? "" : a.toString();
                if ("*".equals(s) || s.contains("*")) {
                    findings.add(new OwaspTestFinding(
                        "A05: Security Misconfiguration",
                        "File upload accepts any file type",
                        page.url(),
                        "accept=" + s
                    ));
                }
            }
        } catch (Exception ignored) {}

        return findings;
    }
}
