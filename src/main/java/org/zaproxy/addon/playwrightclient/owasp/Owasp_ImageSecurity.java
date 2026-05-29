package org.zaproxy.addon.playwrightclient.owasp;

import com.microsoft.playwright.Page;
import java.util.*;

public class Owasp_ImageSecurity {

    private static final String HOOK_SCRIPT =
        "() => {" +
        "  if (window.__imgSecInstalled) return;" +
        "  window.__imgSecInstalled = true;" +
        "  window.__imgSecCalls__ = [];" +
        "  var origToDataURL = HTMLCanvasElement.prototype.toDataURL;" +
        "  HTMLCanvasElement.prototype.toDataURL = function() {" +
        "    window.__imgSecCalls__.push({ type: 'canvas-toDataURL' });" +
        "    return origToDataURL.apply(this, arguments);" +
        "  };" +
        "  var origToBlob = HTMLCanvasElement.prototype.toBlob;" +
        "  HTMLCanvasElement.prototype.toBlob = function() {" +
        "    window.__imgSecCalls__.push({ type: 'canvas-toBlob' });" +
        "    return origToBlob.apply(this, arguments);" +
        "  };" +
        "  var origSendBeacon = navigator.sendBeacon;" +
        "  navigator.sendBeacon = function(url, data) {" +
        "    window.__imgSecCalls__.push({ type: 'sendBeacon', url: url || '' });" +
        "    return origSendBeacon.apply(this, arguments);" +
        "  };" +
        "}";

    public static List<OwaspTestFinding> test(Page page) {
        List<OwaspTestFinding> findings = new ArrayList<>();

        try {
            page.addInitScript(HOOK_SCRIPT);
            page.evaluate(HOOK_SCRIPT);

            try { Thread.sleep(1000); } catch (InterruptedException e) {}

            String pageUrl = page.url();
            boolean isHttps = pageUrl.startsWith("https://");

            Object raw = page.evaluate(
                "() => { " +
                "  var issues = []; " +
                "  var evts = ['onerror','onload','onabort']; " +
                "  document.querySelectorAll('img').forEach(function(img) { " +
                "    var src = img.getAttribute('src') || ''; " +
                "    var w = parseInt(img.getAttribute('width')) || img.naturalWidth || 0;" +
                "    var h = parseInt(img.getAttribute('height')) || img.naturalHeight || 0;" +
                "    for (var i = 0; i < evts.length; i++) {" +
                "      if (img.hasAttribute(evts[i])) " +
                "        issues.push({ type: 'img-event', detail: '<img> has ' + evts[i] + ' handler', src: src });" +
                "    }" +
                "    if (src.startsWith('http://')) " +
                "      issues.push({ type: 'img-http', detail: 'Image loaded over HTTP', src: src });" +
                "    if ((w === 1 || h === 1) && src.length > 0) " +
                "      issues.push({ type: 'tracking-pixel', detail: 'Possible tracking pixel (1x1 image)', src: src });" +
                "    if (src.startsWith('data:image/')) " +
                "      issues.push({ type: 'data-uri', detail: 'Inline base64 image', src: src.substring(0, 80) + '...' });" +
                "  });" +
                "  return issues; " +
                "}"
            );

            if (raw instanceof List) {
                for (Object item : (List<?>) raw) {
                    if (item == null) continue;
                    Map<?, ?> r = (Map<?, ?>) item;
                    String type = String.valueOf(r.get("type"));
                    String detail = String.valueOf(r.get("detail"));
                    String src = String.valueOf(r.get("src"));

                    String cat;
                    switch (type) {
                        case "img-event":
                            cat = "A03: Injection";
                            break;
                        case "img-http":
                            cat = "A02: Cryptographic Failures";
                            break;
                        case "tracking-pixel":
                        case "data-uri":
                            cat = "A04: Insecure Design";
                            break;
                        default:
                            cat = "A04: Insecure Design";
                    }
                    findings.add(new OwaspTestFinding(cat, detail, pageUrl, src));
                }
            }

            Object hookRaw = page.evaluate("() => { var arr = window.__imgSecCalls__ || []; window.__imgSecCalls__ = []; return arr; }");
            if (hookRaw instanceof List) {
                for (Object item : (List<?>) hookRaw) {
                    if (item == null) continue;
                    Map<?, ?> c = (Map<?, ?>) item;
                    String type = String.valueOf(c.get("type"));
                    if ("canvas-toDataURL".equals(type)) {
                        findings.add(new OwaspTestFinding(
                            "A02: Cryptographic Failures",
                            "Canvas toDataURL() called — possible client-side data exfiltration",
                            pageUrl,
                            "Canvas data may be extracted"
                        ));
                    } else if ("canvas-toBlob".equals(type)) {
                        findings.add(new OwaspTestFinding(
                            "A02: Cryptographic Failures",
                            "Canvas toBlob() called — possible client-side data exfiltration",
                            pageUrl,
                            "Canvas data may be extracted"
                        ));
                    } else if ("sendBeacon".equals(type)) {
                        String beaconUrl = String.valueOf(c.get("url"));
                        findings.add(new OwaspTestFinding(
                            "A04: Insecure Design",
                            "navigator.sendBeacon() used — user data may be exfiltrated",
                            pageUrl,
                            beaconUrl.isEmpty() ? "sendBeacon detected" : "sendBeacon URL: " + beaconUrl
                        ));
                    }
                }
            }
        } catch (Exception ignored) {}

        return findings;
    }
}
