package org.zaproxy.addon.playwrightclient.owasp;

import com.microsoft.playwright.Page;
import java.util.*;
import java.util.regex.*;

public class Owasp_PostMessage_Origin {

    public static List<OwaspTestFinding> test(Page page) {
        List<OwaspTestFinding> findings = new ArrayList<>();

        try {
            String content = page.content();
            if (content == null) return findings;

            Pattern listenerPattern = Pattern.compile(
                "addEventListener\\(\\s*(['\"])message\\1\\s*,"
            );
            Matcher matcher = listenerPattern.matcher(content);

            while (matcher.find()) {
                int start = matcher.start();
                int end = Math.min(start + 300, content.length());
                String snippet = content.substring(start, end);

                boolean checksOrigin = snippet.contains(".origin") || snippet.contains("origin === ")
                    || snippet.contains("origin !==") || snippet.contains("event.data")
                    || snippet.contains("e.origin") || snippet.contains("evt.origin");

                if (!checksOrigin) {
                    findings.add(new OwaspTestFinding(
                        "A08: Software & Data Integrity Failures",
                        "postMessage listener may lack origin validation",
                        page.url(),
                        snippet.length() > 120 ? snippet.substring(0, 120) + "..." : snippet
                    ));
                }
            }
        } catch (Exception ignored) {}

        return findings;
    }
}
