package org.zaproxy.addon.playwrightclient;

import com.microsoft.playwright.*;
import com.microsoft.playwright.options.Proxy;
import java.util.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PlaywrightCrawler {

    private final Set<String> discoveredUrls = new HashSet<>();
    private final Set<String> visitedUrls = new HashSet<>();
    private final Queue<String> queue = new ArrayDeque<>();

    private final String baseUrl;
    private final String zapProxy;

    public PlaywrightCrawler(String baseUrl, String zapProxy) {
        this.baseUrl = baseUrl;
        this.zapProxy = zapProxy;
        queue.add(baseUrl);
    }

    public Set<String> crawl() {
        final Logger LOGGER = LoggerFactory.getLogger(PlaywrightCrawler.class);
        LOGGER.info("Starting crawl for baseUrl: {}", baseUrl);

        try (Playwright pw = Playwright.create()) {
            LOGGER.info("Playwright instance created: {}", pw.getClass().getName());

            BrowserType.LaunchOptions opts = new BrowserType.LaunchOptions()
                .setHeadless(true)
                .setProxy(new Proxy(zapProxy));

            Browser browser = pw.chromium().launch(opts);
            LOGGER.info("Browser launched");
            BrowserContext context = browser.newContext(new Browser.NewContextOptions().setIgnoreHTTPSErrors(true));

            context.onRequest(req -> discoveredUrls.add(req.url()));

            Page page = context.newPage();

            while (!queue.isEmpty()) {
                String url = queue.poll();
                if (visitedUrls.contains(url)) continue;

                visitedUrls.add(url);

                try {
                    page.navigate(url);
                    extractLinks(page);
                } catch (Exception e) {
                    LOGGER.warn("Navigation failed for {}: {}", url, e.getMessage());
                }
            }
        } catch (Exception e) {
            LoggerFactory.getLogger(PlaywrightCrawler.class).error("Playwright crawler failed", e);
            throw e;
        }

        return discoveredUrls;
    }

    @SuppressWarnings("unchecked")
    private void extractLinks(Page page) {
        Object raw = page.evalOnSelectorAll(
            "a[href], button[onclick], *[data-link]",
            "els => els.map(e => e.href || e.getAttribute('onclick') || e.dataset.link)"
        );

        List<?> links = raw instanceof List ? (List<?>) raw : Collections.emptyList();

        for (Object linkObj : links) {
            if (linkObj == null) continue;
            String link = linkObj.toString();
            if (!link.startsWith(baseUrl)) continue;
            if (visitedUrls.contains(link)) continue;

            queue.add(link);
            discoveredUrls.add(link);
        }
    }
}
