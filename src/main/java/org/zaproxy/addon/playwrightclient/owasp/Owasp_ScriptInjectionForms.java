package org.zaproxy.addon.playwrightclient.owasp;

import com.microsoft.playwright.Page;
import java.util.*;

public class Owasp_ScriptInjectionForms {

    public static List<OwaspTestFinding> test(Page page) {
        List<OwaspTestFinding> findings = new ArrayList<>();

        try {
            Object raw = page.evaluate(
                "() => { " +
                "  const issues = []; " +
                "  document.querySelectorAll('input[type=text], input[type=search], textarea').forEach(el => { " +
                "    const name = el.name || el.id || '(unnamed)'; " +
                "    const hasPattern = el.hasAttribute('pattern'); " +
                "    if (!hasPattern) { " +
                "      issues.push({ " +
                "        tag: el.tagName.toLowerCase(), " +
                "        name: name, " +
                "        type: el.type || '', " +
                "        reason: 'no pattern validation' " +
                "      }); " +
                "    } " +
                "  }); " +
                "  document.querySelectorAll('input[type=hidden]').forEach(el => { " +
                "    const val = el.value || ''; " +
                "    if (val.includes('<') || val.includes('>') || val.includes('\"') || val.includes(\"'\") || val.includes('&')) { " +
                "      issues.push({ " +
                "        tag: 'input[hidden]', " +
                "        name: el.name || el.id || '(unnamed)', " +
                "        type: 'hidden', " +
                "        reason: 'hidden field contains encoded/special characters' " +
                "      }); " +
                "    } " +
                "  }); " +
                "  return issues; " +
                "}"
            );
            if (!(raw instanceof List)) return findings;

            for (Object item : (List<?>) raw) {
                if (item == null) continue;
                Map<?, ?> issue = (Map<?, ?>) item;
                String tag = String.valueOf(issue.get("tag"));
                String name = String.valueOf(issue.get("name"));
                String reason = String.valueOf(issue.get("reason"));

                findings.add(new OwaspTestFinding(
                    "A03: Injection",
                    "Form input lacks validation — potential script injection vector",
                    page.url(),
                    "<" + tag + " name=\"" + name + "\"> " + reason
                ));
            }
        } catch (Exception ignored) {}

        return findings;
    }
}
