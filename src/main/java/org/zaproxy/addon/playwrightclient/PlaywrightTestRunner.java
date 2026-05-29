package org.zaproxy.addon.playwrightclient;

import com.microsoft.playwright.*;
import com.microsoft.playwright.options.Proxy;
import org.zaproxy.addon.playwrightclient.owasp.OwaspTestFinding;
import org.zaproxy.addon.playwrightclient.owasp.OwaspTestSuite;
import org.zaproxy.addon.playwrightclient.owasp.Owasp_AjaxCallDetection;

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
            BrowserContext context = browser.newContext(new Browser.NewContextOptions().setIgnoreHTTPSErrors(true));

            Owasp_AjaxCallDetection.reset();

            for (String url : urls) {
                try {
                    Page page = context.newPage();
                    page.navigate(url);

                    List<OwaspTestFinding> findings = OwaspTestSuite.runAll(page, context, baseUrl);

                    for (OwaspTestFinding f : findings) {
                        alertService.createAlert(f);
                    }

                    page.close();
                } catch (Exception e) {
                    LOGGER.error("Error processing {}: {}", url, e.getMessage(), e);
                }
            }

            Set<String> ajaxUrls = Owasp_AjaxCallDetection.getDiscoveredAjaxUrls();
            Set<String> allUrls = new HashSet<>(urls);
            if (!ajaxUrls.isEmpty()) {
                LOGGER.info("Discovered {} AJAX URL(s) — adding to scan scope", ajaxUrls.size());
                for (String ajaxUrl : ajaxUrls) {
                    allUrls.add(ajaxUrl);
                    try {
                        Page p = context.newPage();
                        p.navigate(ajaxUrl);
                        p.close();
                    } catch (Exception e) {
                        LOGGER.debug("Skipped navigation to AJAX URL (not a page?): {}", ajaxUrl);
                    }
                }
            }

            try {
                zapOrchestrator.scanUrls(allUrls);
            } catch (Exception ignored) {}

            browser.close();
        } catch (Exception e) {
            LOGGER.error("Runner failed: {}", e.getMessage(), e);
        }
    }
}
