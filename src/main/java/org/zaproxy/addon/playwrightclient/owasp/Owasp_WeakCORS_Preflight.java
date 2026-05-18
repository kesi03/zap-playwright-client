package org.zaproxy.addon.playwrightclient.owasp;

import com.microsoft.playwright.Page;
import java.util.*;

public class Owasp_WeakCORS_Preflight {

    public static List<OwaspTestFinding> test(Page page) {
        List<OwaspTestFinding> findings = new ArrayList<>();

        try {
            page.onRequest(req -> {
                String method = req.method();
                if ("OPTIONS".equalsIgnoreCase(method)) {
                    // preflight observed; inspect response headers via onResponse
                }
            });

            page.onResponse(res -> {
                Map<String,String> headers = res.headers();
                String acao = headers.get("access-control-allow-origin");
                String acam = headers.get("access-control-allow-methods");
                if (acao != null && "*".equals(acao) && (acam == null || acam.contains("*") )) {
                    findings.add(new OwaspTestFinding(
                        "A05: Security Misconfiguration",
                        "Weak CORS preflight handling",
                        res.url(),
                        "Access-Control headers allow broad access"
                    ));
                }
            });
        } catch (Exception ignored) {}

        return findings;
    }
}
