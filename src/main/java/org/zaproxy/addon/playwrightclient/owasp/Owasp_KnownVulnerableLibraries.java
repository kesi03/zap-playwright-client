package org.zaproxy.addon.playwrightclient.owasp;

import com.microsoft.playwright.Page;
import java.util.*;

public class Owasp_KnownVulnerableLibraries {

    public static List<OwaspTestFinding> test(Page page) {
        List<OwaspTestFinding> findings = new ArrayList<>();

        try {
            Object raw = page.evaluate(
                "() => { " +
                "  const libs = {}; " +
                "  if (typeof jQuery !== 'undefined' && jQuery.fn && jQuery.fn.jquery) " +
                "    libs.jQuery = jQuery.fn.jquery; " +
                "  if (typeof angular !== 'undefined' && angular.version) " +
                "    libs.Angular = angular.version.full || angular.version; " +
                "  if (typeof Vue !== 'undefined' && Vue.version) " +
                "    libs.Vue = Vue.version; " +
                "  if (typeof React !== 'undefined' && React.version) " +
                "    libs.React = React.version; " +
                "  if (typeof Backbone !== 'undefined') " +
                "    libs.Backbone = 'detected'; " +
                "  if (typeof _ !== 'undefined' && _.VERSION) " +
                "    libs.Underscore = _.VERSION; " +
                "  if (typeof moment !== 'undefined' && moment.version) " +
                "    libs.Moment = moment.version; " +
                "  if (typeof io !== 'undefined') " +
                "    libs.SocketIO = 'detected'; " +
                "  if (typeof bootstrap !== 'undefined' && bootstrap.Dropdown) " +
                "    libs.Bootstrap = 'detected (v5+)'; " +
                "  if (typeof $ !== 'undefined' && $.fn && $.fn.modal) " +
                "    libs.Bootstrap = libs.Bootstrap || 'detected (v3/v4 via jQuery)'; " +
                "  return libs; " +
                "}"
            );
            if (!(raw instanceof Map)) return findings;

            Map<?, ?> libs = (Map<?, ?>) raw;
            for (Map.Entry<?, ?> entry : libs.entrySet()) {
                String name = String.valueOf(entry.getKey());
                String version = String.valueOf(entry.getValue());
                findings.add(new OwaspTestFinding(
                    "A06: Vulnerable & Outdated Components",
                    "Detected JavaScript library — verify version for known vulnerabilities",
                    page.url(),
                    name + " " + version
                ));
            }
        } catch (Exception ignored) {}

        return findings;
    }
}
