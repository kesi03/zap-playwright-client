package org.zaproxy.addon.playwrightclient;

import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.ConnectionParam;
import org.zaproxy.zap.extension.api.API;

public class ExtensionPlaywrightClient extends ExtensionAdaptor {

    public static final String NAME = "ExtensionPlaywrightClient";

    public ExtensionPlaywrightClient() {
        super(NAME);
    }

    @Override
    public void hook(ExtensionHook hook) {
        super.hook(hook);

        // Add API endpoints if needed
        PlaywrightClientApi api = new PlaywrightClientApi(this);
        hook.addApiImplementor(api);
        try {
            API.getInstance().registerApiImplementor(api);
        } catch (Exception e) {
            // Registration via API singleton is optional; ignore failures
        }
    }

    public void runCrawlAndScan(String baseUrl) {
        String zapProxy = getZapProxy();
        PlaywrightCrawler crawler = new PlaywrightCrawler(baseUrl, zapProxy);
        var urls = crawler.crawl();

        // Run Playwright tests against discovered URLs and create ZAP alerts
        PlaywrightTestRunner runner = new PlaywrightTestRunner(zapProxy);
        runner.runTests(urls, baseUrl);
    }

    private String getZapProxy() {
        ConnectionParam conn = Model.getSingleton().getOptionsParam().getConnectionParam();
        String host = conn.getProxyChainName();
        int port = conn.getProxyChainPort();

        if (host == null || host.isEmpty()) {
            host = "localhost"; // fallback
        }

        return "http://" + host + ":" + port;
    }
}
