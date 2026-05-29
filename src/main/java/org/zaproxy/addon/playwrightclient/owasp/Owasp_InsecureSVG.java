package org.zaproxy.addon.playwrightclient.owasp;

import com.microsoft.playwright.Page;
import java.util.*;

public class Owasp_InsecureSVG {

    public static List<OwaspTestFinding> test(Page page) {
        List<OwaspTestFinding> findings = new ArrayList<>();

        try {
            Object raw = page.evaluate(
                "() => { " +
                "  var results = []; " +
                "  document.querySelectorAll('svg').forEach(function(svg) { " +
                "    if (svg.querySelector('script')) " +
                "      results.push({ type: 'script-in-svg', desc: '<script> inside <svg>', svg: svg.outerHTML.substring(0, 200) }); " +
                "    if (svg.querySelector('foreignObject')) " +
                "      results.push({ type: 'foreignObject', desc: '<foreignObject> in SVG allows HTML embedding', svg: svg.outerHTML.substring(0, 200) }); " +
                "    svg.querySelectorAll('use').forEach(function(u) { " +
                "      var h = u.getAttribute('href') || u.getAttribute('xlink:href') || ''; " +
                "      if (h.startsWith('http')) " +
                "        results.push({ type: 'external-use', desc: '<use> references external resource', svg: h }); " +
                "    }); " +
                "    var evts = ['onload','onerror','onclick','onmouseover','onfocus','onblur','onresize','onscroll']; " +
                "    svg.querySelectorAll('*').forEach(function(el) { " +
                "      for (var i = 0; i < evts.length; i++) { " +
                "        if (el.hasAttribute(evts[i])) " +
                "          results.push({ type: 'svg-event', desc: 'SVG element has ' + evts[i] + ' handler', svg: el.outerHTML.substring(0, 200) }); " +
                "      } " +
                "    }); " +
                "  }); " +
                "  return results; " +
                "}"
            );
            if (!(raw instanceof List)) return findings;

            for (Object item : (List<?>) raw) {
                if (item == null) continue;
                Map<?, ?> r = (Map<?, ?>) item;
                String type = String.valueOf(r.get("type"));
                String desc = String.valueOf(r.get("desc"));
                String svg = String.valueOf(r.get("svg"));

                findings.add(new OwaspTestFinding(
                    "A03: Injection",
                    "Insecure SVG: " + desc,
                    page.url(),
                    svg
                ));
            }
        } catch (Exception ignored) {}

        return findings;
    }
}
