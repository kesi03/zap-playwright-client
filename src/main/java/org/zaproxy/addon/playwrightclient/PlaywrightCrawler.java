package org.zaproxy.addon.playwrightclient;

import com.microsoft.playwright.*;
import com.microsoft.playwright.options.Proxy;
import java.util.*;

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
        try (Playwright pw = Playwright.create()) {

            BrowserType.LaunchOptions opts = new BrowserType.LaunchOptions()
                .setHeadless(true)
                .setProxy(new Proxy(zapProxy));

            Browser browser = pw.chromium().launch(opts);
            BrowserContext context = browser.newContext();

            context.onRequest(req -> discoveredUrls.add(req.url()));

            Page page = context.newPage();

            while (!queue.isEmpty()) {
                String url = queue.poll();
                if (visitedUrls.contains(url)) continue;

                visitedUrls.add(url);

                try {
                    page.navigate(url);
                    extractLinks(page);
                } catch (Exception ignored) {}
            }
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
