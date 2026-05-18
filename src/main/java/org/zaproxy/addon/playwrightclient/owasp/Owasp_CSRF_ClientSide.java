package org.zaproxy.addon.playwrightclient.owasp;

import com.microsoft.playwright.BrowserContext;
import java.util.*;

public class Owasp_CSRF_ClientSide {

    public static List<OwaspTestFinding> test(BrowserContext context) {
        List<OwaspTestFinding> findings = new ArrayList<>();

        try {
            List<?> cookies = (List<?>) context.cookies();
            for (Object c : cookies) {
                try {
                    Class<?> cc = c.getClass();
                    java.lang.reflect.Method mName = null;
                    try { mName = cc.getMethod("name"); } catch (Exception e) {}
                    String name = mName != null ? String.valueOf(mName.invoke(c)) : null;

                    java.lang.reflect.Method mSame = null;
                    try { mSame = cc.getMethod("sameSite"); } catch (Exception e) {}
                    Object same = mSame != null ? mSame.invoke(c) : null;

                    if (name != null && name.equalsIgnoreCase("session") && same == null) {
                        findings.add(new OwaspTestFinding(
                            "A01: Broken Access Control",
                            "Session cookie missing SameSite attribute",
                            name,
                            "Cookie: " + name
                        ));
                    }
                } catch (Exception ignored) {}
            }
        } catch (Exception ignored) {}

        return findings;
    }
}
