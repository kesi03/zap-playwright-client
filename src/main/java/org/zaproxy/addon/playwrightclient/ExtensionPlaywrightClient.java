package org.zaproxy.addon.playwrightclient;

import com.microsoft.playwright.*;
import com.microsoft.playwright.options.Proxy;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.zaproxy.addon.automation.ExtensionAutomation;
import org.zaproxy.addon.playwrightclient.automation.PlaywrightJob;
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

        ExtensionAutomation extAuto =
                Control.getSingleton()
                        .getExtensionLoader()
                        .getExtension(ExtensionAutomation.class);
        if (extAuto != null) {
            extAuto.registerAutomationJob(new PlaywrightJob());
        } else {
            LOGGER.warn("Automation add-on not available — skipping automation job registration");
        }
    }

    private static void ensureDriverDir() {
        if (System.getProperty("playwright.cli.dir") != null) return;
        String nodePath = System.getenv("PLAYWRIGHT_NODEJS_PATH");
        if (nodePath != null && !nodePath.isEmpty()) {
            Path dir = Paths.get(nodePath).getParent();
            if (dir != null && Files.exists(dir)) {
                System.setProperty("playwright.cli.dir", dir.toString());
            }
        }
    }

    public void runCrawlAndScan(String baseUrl) {
        ensureDriverDir();
        String zapProxy = getZapProxy();
        PlaywrightCrawler crawler = new PlaywrightCrawler(baseUrl, zapProxy);
        var urls = crawler.crawl();

        PlaywrightTestRunner runner = new PlaywrightTestRunner(zapProxy);
        runner.runTests(urls, baseUrl);
    }

    public Path takeScreenshot(String url) {
        ensureDriverDir();
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
            BrowserContext context = browser.newContext(new Browser.NewContextOptions().setIgnoreHTTPSErrors(true));
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
