package org.zaproxy.addon.playwrightclient.owasp;

import com.microsoft.playwright.Page;
import java.util.*;

public class Owasp_NpmPackageDetection {

    public static List<OwaspTestFinding> test(Page page) {
        List<OwaspTestFinding> findings = new ArrayList<>();

        try {
            Object raw = page.evaluate(
                "() => { " +
                "  const markers = []; " +
                "  if (typeof __webpack_require__ !== 'undefined') " +
                "    markers.push('webpack bundle system'); " +
                "  if (typeof __NUXT__ !== 'undefined') " +
                "    markers.push('Nuxt.js'); " +
                "  if (typeof __NEXT_DATA__ !== 'undefined') " +
                "    markers.push('Next.js'); " +
                "  if (typeof process !== 'undefined' && process.env) " +
                "    markers.push('bundled process.env'); " +
                "  if (typeof __VUE_OPTIONS_API__ !== 'undefined') " +
                "    markers.push('Vue CLI'); " +
                "  if (typeof SENTRY_RELEASE !== 'undefined') " +
                "    markers.push('Sentry SDK'); " +
                "  if (typeof __SENTRY__ !== 'undefined') " +
                "    markers.push('Sentry SDK'); " +
                "  if (typeof ga !== 'undefined') " +
                "    markers.push('Google Analytics'); " +
                "  if (typeof gtag !== 'undefined') " +
                "    markers.push('Google Tag Manager'); " +
                "  if (typeof fbq !== 'undefined') " +
                "    markers.push('Facebook Pixel'); " +
                "  return markers; " +
                "}"
            );
            if (raw instanceof List) {
                for (Object m : (List<?>) raw) {
                    if (m == null) continue;
                    findings.add(new OwaspTestFinding(
                        "A06: Vulnerable & Outdated Components",
                        "Detected npm-based JavaScript framework — verify version for known vulnerabilities",
                        page.url(),
                        String.valueOf(m)
                    ));
                }
            }

            String content = page.content();
            if (content != null) {
                if (content.contains("/node_modules/")) {
                    findings.add(new OwaspTestFinding(
                        "A06: Vulnerable & Outdated Components",
                        "Source code may reference node_modules path — possible source map exposure",
                        page.url(),
                        "node_modules/ reference found in page"
                    ));
                }
            }
        } catch (Exception ignored) {}

        return findings;
    }
}
