package org.zaproxy.addon.playwrightclient.owasp;

import com.microsoft.playwright.Page;
import java.util.*;

public class Owasp_LoginOverHTTP {

    public static List<OwaspTestFinding> test(Page page) {
        List<OwaspTestFinding> findings = new ArrayList<>();

        try {
            Object raw = page.evaluate(
                "() => Array.from(document.querySelectorAll('form')).map(f => ({ " +
                "  action: f.action || '', " +
                "  id: f.id || '', " +
                "  hasPassword: !!f.querySelector('input[type=password]') " +
                "}))"
            );
            if (!(raw instanceof List)) return findings;

            for (Object item : (List<?>) raw) {
                if (item == null) continue;
                Map<?, ?> form = (Map<?, ?>) item;
                String action = String.valueOf(form.get("action"));
                boolean hasPassword = Boolean.TRUE.equals(form.get("hasPassword"));

                if (hasPassword && action.startsWith("http://")) {
                    findings.add(new OwaspTestFinding(
                        "A07: Identification & Authentication Failures",
                        "Login form submits credentials over HTTP",
                        page.url(),
                        "Form action: " + action
                    ));
                }
            }
        } catch (Exception ignored) {}

        return findings;
    }
}
