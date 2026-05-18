package org.zaproxy.addon.playwrightclient.owasp;

import com.microsoft.playwright.Page;
import java.util.*;

public class Owasp_WebSocket_Insecure {

    public static List<OwaspTestFinding> test(Page page) {
        List<OwaspTestFinding> findings = new ArrayList<>();

        try {
            page.onWebSocket(ws -> {
                if (ws.url() != null && ws.url().startsWith("ws://")) {
                    findings.add(new OwaspTestFinding(
                        "A02: Cryptographic Failures",
                        "Insecure WebSocket connection",
                        ws.url(),
                        "ws:// used instead of wss://"
                    ));
                }
            });
        } catch (Exception ignored) {}

        return findings;
    }
}
