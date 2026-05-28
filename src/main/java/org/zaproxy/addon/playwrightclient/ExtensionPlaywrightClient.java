package org.zaproxy.addon.playwrightclient;

import com.microsoft.playwright.*;
import com.microsoft.playwright.options.Proxy;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ExtensionPlaywrightClient extends ExtensionAdaptor {

    private static final Logger LOGGER = LoggerFactory.getLogger(ExtensionPlaywrightClient.class);

    public static final String NAME = "ExtensionPlaywrightClient";

    public ExtensionPlaywrightClient() {
        super(NAME);
    }

    @Override
    public void hook(ExtensionHook hook) {
        super.hook(hook);

        hook.addApiImplementor(new PlaywrightClientApi(this));
    }

    public void runCrawlAndScan(String baseUrl) {
        String zapProxy = getZapProxy();
        PlaywrightCrawler crawler = new PlaywrightCrawler(baseUrl, zapProxy);
        var urls = crawler.crawl();

        PlaywrightTestRunner runner = new PlaywrightTestRunner(zapProxy);
        runner.runTests(urls, baseUrl);
    }

    public Path takeScreenshot(String url) {
        String zapProxy = getZapProxy();
        Path dir = getScreenshotDir();
        dir.toFile().mkdirs();

        String ts = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss"));
        String safeName = url.replaceAll("[^a-zA-Z0-9.-]", "_");
        Path out = dir.resolve(safeName + "_" + ts + ".png");

        try (Playwright pw = Playwright.create()) {
            BrowserType.LaunchOptions opts = new BrowserType.LaunchOptions()
                .setHeadless(true)
                .setProxy(new Proxy(zapProxy));
            Browser browser = pw.chromium().launch(opts);
            BrowserContext context = browser.newContext();
            Page page = context.newPage();
            page.navigate(url);
            page.screenshot(new Page.ScreenshotOptions().setPath(out));
            browser.close();
            LOGGER.info("Saved screenshot to {}", out);
        } catch (Exception e) {
            LOGGER.error("Screenshot failed for {}: {}", url, e.getMessage());
            throw new RuntimeException("Screenshot failed for " + url, e);
        }

        return out;
    }

    public Path getScreenshotDir() {
        String home = Constant.getZapHome();
        if (home == null) {
            home = System.getProperty("user.home", ".");
        }
        return Paths.get(home, "screenshots");
    }

    private String getZapProxy() {
        return "localhost:8080";
    }
}
