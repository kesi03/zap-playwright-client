package org.zaproxy.addon.playwrightclient.owasp;

import com.microsoft.playwright.Page;
import java.util.*;

public class Owasp_GraphQL_Introspection {

    public static List<OwaspTestFinding> test(Page page, String baseUrl) {
        List<OwaspTestFinding> findings = new ArrayList<>();

        try {
            String query = "{\"query\":\"{ __schema { types { name } } }\"}";

            Object result = page.evaluate("async (data) => { const res = await fetch(data.url, {method:'POST', headers:{'Content-Type':'application/json'}, body: data.body}); return await res.text(); }", java.util.Map.of("url", baseUrl + "/graphql", "body", query));


            if (result != null && result.toString().contains("__schema")) {
                findings.add(new OwaspTestFinding(
                    "A05: Security Misconfiguration",
                    "GraphQL introspection enabled in production",
                    baseUrl + "/graphql",
                    "Introspection query returned schema"
                ));
            }
        } catch (Exception ignored) {}

        return findings;
    }
}
