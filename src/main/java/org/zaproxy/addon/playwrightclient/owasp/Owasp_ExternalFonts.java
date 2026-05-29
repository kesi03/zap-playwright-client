package org.zaproxy.addon.playwrightclient.owasp;

import com.microsoft.playwright.Page;
import java.util.*;

public class Owasp_ExternalFonts {

    public static List<OwaspTestFinding> test(Page page) {
        List<OwaspTestFinding> findings = new ArrayList<>();

        try {
            Object raw = page.evaluate(
                "() => { " +
                "  var fonts = []; " +
                "  for (var i = 0; i < document.styleSheets.length; i++) { " +
                "    try { " +
                "      var sheet = document.styleSheets[i]; " +
                "      for (var j = 0; j < (sheet.cssRules || []).length; j++) { " +
                "        var rule = sheet.cssRules[j]; " +
                "        if (rule.type === 5) { " +
                "          var src = rule.style.getPropertyValue('src') || ''; " +
                "          var family = rule.style.getPropertyValue('font-family') || ''; " +
                "          fonts.push({ src: src, family: family }); " +
                "        } " +
                "      } " +
                "    } catch(e) {} " +
                "  } " +
                "  return fonts; " +
                "}"
            );
            if (!(raw instanceof List)) return findings;

            String pageOrigin = "";
            try {
                java.net.URL u = new java.net.URL(page.url());
                pageOrigin = u.getProtocol() + "://" + u.getHost();
                if (u.getPort() > 0 && u.getPort() != 80 && u.getPort() != 443) {
                    pageOrigin += ":" + u.getPort();
                }
            } catch (Exception ignored) {}

            for (Object item : (List<?>) raw) {
                if (item == null) continue;
                Map<?, ?> f = (Map<?, ?>) item;
                String src = String.valueOf(f.get("src"));
                String family = String.valueOf(f.get("family"));

                if (src.contains("http://")) {
                    findings.add(new OwaspTestFinding(
                        "A02: Cryptographic Failures",
                        "Font loaded over unencrypted HTTP",
                        page.url(),
                        "Font: " + family + " — " + src
                    ));
                }

                if (!pageOrigin.isEmpty() && !src.contains(pageOrigin) && (src.contains("url(http") || src.contains("url('http") || src.contains("url(\\\"http"))) {
                    findings.add(new OwaspTestFinding(
                        "A04: Insecure Design",
                        "External font loaded from third-party origin — potential privacy tracking via font fingerprinting",
                        page.url(),
                        "Font: " + family + " — " + src
                    ));
                }
            }
        } catch (Exception ignored) {}

        return findings;
    }
}
