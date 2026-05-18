package org.zaproxy.addon.playwrightclient.owasp;

import com.microsoft.playwright.BrowserContext;

import java.lang.reflect.Method;
import java.util.*;

public class OwaspA02_CryptographicFailures {

    public static List<OwaspTestFinding> test(BrowserContext context) {
        List<OwaspTestFinding> findings = new ArrayList<>();

        List<?> cookies = (List<?>) context.cookies();

        for (Object c : cookies) {
            try {
                Class<?> cc = c.getClass();

                Boolean secure = invokeBoolean(cc, c, "secure", "isSecure");
                Boolean httpOnly = invokeBoolean(cc, c, "httpOnly", "isHttpOnly");
                Object sameSite = invokeObject(cc, c, "sameSite", "getSameSite");

                String domain = invokeString(cc, c, "domain", "getDomain");
                String name = invokeString(cc, c, "name", "getName");

                if (secure != null && !secure) {
                    findings.add(new OwaspTestFinding(
                        "A02: Cryptographic Failures",
                        "Cookie missing Secure flag",
                        domain == null ? "" : domain,
                        name == null ? "" : name
                    ));
                }

                if (httpOnly != null && !httpOnly) {
                    findings.add(new OwaspTestFinding(
                        "A02: Cryptographic Failures",
                        "Cookie missing HttpOnly flag",
                        domain == null ? "" : domain,
                        name == null ? "" : name
                    ));
                }

                if (sameSite == null) {
                    findings.add(new OwaspTestFinding(
                        "A02: Cryptographic Failures",
                        "Cookie missing SameSite attribute",
                        domain == null ? "" : domain,
                        name == null ? "" : name
                    ));
                }

            } catch (Exception ignored) {}
        }

        return findings;
    }

    private static Boolean invokeBoolean(Class<?> cc, Object obj, String... names) {
        for (String n : names) {
            try {
                Method m = cc.getMethod(n);
                Object r = m.invoke(obj);
                if (r instanceof Boolean) return (Boolean) r;
            } catch (Exception ignored) {}
        }
        return null;
    }

    private static String invokeString(Class<?> cc, Object obj, String... names) {
        for (String n : names) {
            try {
                Method m = cc.getMethod(n);
                Object r = m.invoke(obj);
                if (r != null) return r.toString();
            } catch (Exception ignored) {}
        }
        return null;
    }

    private static Object invokeObject(Class<?> cc, Object obj, String... names) {
        for (String n : names) {
            try {
                Method m = cc.getMethod(n);
                return m.invoke(obj);
            } catch (Exception ignored) {}
        }
        return null;
    }
}
