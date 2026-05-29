package org.zaproxy.addon.playwrightclient.owasp;

import com.microsoft.playwright.Page;
import java.util.*;

public class Owasp_FormCSRF {

    private static final String[] CSRF_PATTERNS = {
        "csrf", "_token", "authenticity_token", "csrf_token", "csrfmiddlewaretoken",
        "__csrf", "csrf-token", "xsrf", "_csrf_token", "csrfToken"
    };

    public static List<OwaspTestFinding> test(Page page) {
        List<OwaspTestFinding> findings = new ArrayList<>();

        try {
            Object raw = page.evaluate(
                "() => Array.from(document.querySelectorAll('form')).map(f => ({ " +
                "  id: f.id || '', " +
                "  action: f.action || '', " +
                "  method: (f.method || 'get').toLowerCase(), " +
                "  inputs: Array.from(f.querySelectorAll('input, textarea, select')).map(i => ({ " +
                "    type: i.type || '', " +
                "    name: i.name || '', " +
                "    id: i.id || '' " +
                "  })) " +
                "}))"
            );
            if (!(raw instanceof List)) return findings;

            for (Object item : (List<?>) raw) {
                if (item == null) continue;
                Map<?, ?> form = (Map<?, ?>) item;
                String action = String.valueOf(form.get("action"));
                String method = String.valueOf(form.get("method"));

                List<?> inputs = form.get("inputs") instanceof List ? (List<?>) form.get("inputs") : new ArrayList<>();
                boolean hasCsrf = false;
                boolean hasPassword = false;

                for (Object inp : inputs) {
                    if (inp == null) continue;
                    Map<?, ?> input = (Map<?, ?>) inp;
                    String name = String.valueOf(input.get("name"));
                    String type = String.valueOf(input.get("type"));

                    if ("password".equals(type)) hasPassword = true;
                    for (String pattern : CSRF_PATTERNS) {
                        if (name.toLowerCase().contains(pattern)) {
                            hasCsrf = true;
                            break;
                        }
                    }
                    if (hasCsrf) break;
                }

                if (hasPassword && !hasCsrf) {
                    findings.add(new OwaspTestFinding(
                        "A04: Insecure Design",
                        "Login form missing anti-CSRF token",
                        action.isEmpty() ? page.url() : action,
                        "No hidden input with name matching CSRF patterns found"
                    ));
                }
            }
        } catch (Exception ignored) {}

        return findings;
    }
}
