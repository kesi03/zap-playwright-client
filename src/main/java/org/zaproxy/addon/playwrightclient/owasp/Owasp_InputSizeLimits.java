package org.zaproxy.addon.playwrightclient.owasp;

import com.microsoft.playwright.Page;
import java.util.*;

public class Owasp_InputSizeLimits {

    public static List<OwaspTestFinding> test(Page page) {
        List<OwaspTestFinding> findings = new ArrayList<>();

        try {
            Object raw = page.evaluate(
                "() => { " +
                "  const fields = []; " +
                "  document.querySelectorAll('textarea').forEach(el => { " +
                "    if (!el.hasAttribute('maxlength')) " +
                "      fields.push({ tag: 'textarea', name: el.name || el.id || '(unnamed)' }); " +
                "  }); " +
                "  document.querySelectorAll('input[type=text], input[type=search], input[type=url], input[type=email]').forEach(el => { " +
                "    if (!el.hasAttribute('maxlength') && !el.hasAttribute('pattern')) " +
                "      fields.push({ tag: 'input', name: el.name || el.id || '(unnamed)' }); " +
                "  }); " +
                "  return fields; " +
                "}"
            );
            if (!(raw instanceof List)) return findings;

            for (Object item : (List<?>) raw) {
                if (item == null) continue;
                Map<?, ?> field = (Map<?, ?>) item;
                String tag = String.valueOf(field.get("tag"));
                String name = String.valueOf(field.get("name"));

                findings.add(new OwaspTestFinding(
                    "A04: Insecure Design",
                    tag.equals("textarea")
                        ? "Textarea missing maxlength limit — potential large data upload"
                        : "Text input missing maxlength or pattern validation",
                    page.url(),
                    "<" + tag + " name=\"" + name + "\">"
                ));
            }
        } catch (Exception ignored) {}

        return findings;
    }
}
