package org.zaproxy.addon.playwrightclient;

import com.microsoft.playwright.*;
import com.microsoft.playwright.options.Proxy;
import org.zaproxy.addon.playwrightclient.owasp.OwaspTestFinding;
import org.zaproxy.addon.playwrightclient.owasp.OwaspTestSuite;

import java.util.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PlaywrightTestRunner {

    private static final Logger LOGGER = LoggerFactory.getLogger(PlaywrightTestRunner.class);

    private final String zapProxy;
    private final PlaywrightAlertService alertService;
    private final ZapScanOrchestrator zapOrchestrator;

    public PlaywrightTestRunner(String zapProxy) {
        this.zapProxy = zapProxy;
        this.alertService = new PlaywrightAlertService();
        this.zapOrchestrator = new ZapScanOrchestrator();
    }

    public void runTests(Set<String> urls, String baseUrl) {
        try (Playwright pw = Playwright.create()) {
            BrowserType.LaunchOptions opts = new BrowserType.LaunchOptions()
                .setHeadless(true)
                .setProxy(new Proxy(zapProxy));

            Browser browser = pw.chromium().launch(opts);
            BrowserContext context = browser.newContext();

            for (String url : urls) {
                try {
                    Page page = context.newPage();
                    page.navigate(url);

                    List<OwaspTestFinding> findings = OwaspTestSuite.runAll(page, context, baseUrl);

                    for (OwaspTestFinding f : findings) {
                        String evidence = f.evidence != null ? f.evidence : f.description;
                        String alertUrl = (f.url != null && !f.url.isEmpty()) ? f.url : url;
                        alertService.createAlert(alertUrl, evidence);
                    }

                    page.close();
                } catch (Exception e) {
                    LOGGER.error("Error processing {}: {}", url, e.getMessage(), e);
                }
            }

            try {
                zapOrchestrator.scanUrls(urls);
            } catch (Exception ignored) {}

            browser.close();
        } catch (Exception e) {
            LOGGER.error("Runner failed: {}", e.getMessage(), e);
        }
    }
}
