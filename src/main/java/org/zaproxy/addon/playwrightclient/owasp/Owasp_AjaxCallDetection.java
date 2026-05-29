package org.zaproxy.addon.playwrightclient.owasp;

import com.microsoft.playwright.Page;
import java.util.*;

public class Owasp_AjaxCallDetection {

    private static final Set<String> discoveredAjaxUrls = new HashSet<>();

    public static Set<String> getDiscoveredAjaxUrls() {
        return discoveredAjaxUrls;
    }

    public static void reset() {
        discoveredAjaxUrls.clear();
    }

    private static final String HOOK_SCRIPT =
        "() => {" +
        "  if (window.__ajaxMonInstalled) return;" +
        "  window.__ajaxMonInstalled = true;" +
        "  window.__ajaxCalls__ = [];" +
        "  var origFetch = window.fetch;" +
        "  window.fetch = function() {" +
        "    var url = '';" +
        "    var a0 = arguments[0];" +
        "    url = typeof a0 === 'string' ? a0 : (a0 && a0.url ? a0.url : '');" +
        "    var method = (arguments[1] && arguments[1].method) || 'GET';" +
        "    var body = '';" +
        "    try { if (arguments[1] && arguments[1].body) body = String(arguments[1].body).substring(0, 500); } catch(e){}" +
        "    window.__ajaxCalls__.push({ type: 'fetch', url: url, method: method, body: body });" +
        "    return origFetch.apply(this, arguments);" +
        "  };" +
        "  var XHRp = XMLHttpRequest.prototype;" +
        "  var origOpen = XHRp.open;" +
        "  XHRp.open = function(m, u) {" +
        "    this.__ajax = { type: 'xhr', url: typeof u === 'string' ? u : String(u), method: m, body: '' };" +
        "    return origOpen.apply(this, arguments);" +
        "  };" +
        "  var origSend = XHRp.send;" +
        "  XHRp.send = function(b) {" +
        "    if (this.__ajax) {" +
        "      try { this.__ajax.body = b ? String(b).substring(0, 500) : ''; } catch(e){}" +
        "      window.__ajaxCalls__.push(this.__ajax);" +
        "    }" +
        "    return origSend.apply(this, arguments);" +
        "  };" +
        "}";

    public static List<OwaspTestFinding> test(Page page) {
        List<OwaspTestFinding> findings = new ArrayList<>();

        try {
            page.addInitScript(HOOK_SCRIPT);
            page.evaluate(HOOK_SCRIPT);

            try { Thread.sleep(2000); } catch (InterruptedException e) {}

            Object raw = page.evaluate("() => { var arr = window.__ajaxCalls__ || []; window.__ajaxCalls__ = []; return arr; }");
            if (!(raw instanceof List)) return findings;

            Set<String> endpoints = new LinkedHashSet<>();
            boolean hasInternal = false, hasSensitiveBody = false, hasHttp = false;

            for (Object item : (List<?>) raw) {
                if (item == null) continue;
                Map<?, ?> call = (Map<?, ?>) item;
                String url = String.valueOf(call.get("url"));
                String method = String.valueOf(call.get("method"));
                Object bodyObj = call.get("body");
                String body = bodyObj != null ? String.valueOf(bodyObj) : "";

                String clean = url.indexOf('?') > 0 ? url.substring(0, url.indexOf('?')) : url;
                endpoints.add(clean);

                if (url.contains("/admin") || url.contains("/internal") || url.contains("/api/") || url.contains("/private") || url.contains("/rest/")) {
                    hasInternal = true;
                    findings.add(new OwaspTestFinding(
                        "A01: Broken Access Control",
                        "Client-side AJAX call to internal/private API endpoint",
                        url,
                        "Method: " + method
                    ));
                }

                String bl = body.toLowerCase();
                if (bl.contains("password") || bl.contains("secret") || bl.contains("token") || bl.contains("authorization") || bl.contains("apikey")) {
                    hasSensitiveBody = true;
                    findings.add(new OwaspTestFinding(
                        "A04: Insecure Design",
                        "Sensitive data transmitted in AJAX request body",
                        url,
                        "Body contains sensitive keyword"
                    ));
                }

                if (url.startsWith("http://") && !url.contains("localhost") && !url.contains("127.0.0.1") && !url.contains("10.") && !url.contains("192.168.")) {
                    hasHttp = true;
                    findings.add(new OwaspTestFinding(
                        "A02: Cryptographic Failures",
                        "AJAX request sent over unencrypted HTTP",
                        url,
                        "Method: " + method
                    ));
                }
            }

            if (!endpoints.isEmpty()) {
                discoveredAjaxUrls.addAll(endpoints);

                findings.add(new OwaspTestFinding(
                    "A04: Insecure Design",
                    "Discovered " + endpoints.size() + " unique AJAX endpoint(s) from client-side code",
                    page.url(),
                    hasInternal ? "Includes internal API endpoints" : "No internal endpoints detected"
                ));
            }

        } catch (Exception ignored) {}

        return findings;
    }
}
