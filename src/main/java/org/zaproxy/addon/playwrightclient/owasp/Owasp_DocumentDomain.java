package org.zaproxy.addon.playwrightclient.owasp;

import com.microsoft.playwright.Page;
import java.util.*;

public class Owasp_DocumentDomain {

    public static List<OwaspTestFinding> test(Page page) {
        List<OwaspTestFinding> findings = new ArrayList<>();

        try {
            Object raw = page.evaluate(
                "() => { " +
                "  var dd = document.domain; " +
                "  var hn = location.hostname; " +
                "  if (dd && hn && dd !== hn) " +
                "    return { domain: dd, hostname: hn }; " +
                "  return null; " +
                "}"
            );
            if (!(raw instanceof Map)) return findings;

            Map<?, ?> info = (Map<?, ?>) raw;
            String domain = String.valueOf(info.get("domain"));
            String hostname = String.valueOf(info.get("hostname"));

            findings.add(new OwaspTestFinding(
                "A03: Injection",
                "document.domain lowered — weakens same-origin policy",
                page.url(),
                "document.domain set to \"" + domain + "\" (hostname: " + hostname + ")"
            ));
        } catch (Exception ignored) {}

        return findings;
    }
}
