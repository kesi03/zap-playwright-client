package org.zaproxy.addon.playwrightclient;

import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.SiteMap;
import org.parosproxy.paros.model.SiteNode;
import org.zaproxy.zap.extension.ascan.ExtensionActiveScan;
import org.zaproxy.zap.model.Target;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Set;

public class ZapScanOrchestrator {

    private static final Logger LOGGER = LoggerFactory.getLogger(ZapScanOrchestrator.class);

    private final ExtensionActiveScan ext;
    private final Model model;

    public ZapScanOrchestrator() {
        ExtensionActiveScan e = null;
        Model m = null;
        try {
            m = Model.getSingleton();
            e = Control.getSingleton()
                .getExtensionLoader()
                .getExtension(ExtensionActiveScan.class);
        } catch (Exception ignored) {}
        this.ext = e;
        this.model = m;
    }

    public void scanUrls(Set<String> urls) {
        if (ext == null) {
            LOGGER.warn("ExtensionActiveScan not available, skipping active scan");
            return;
        }
        if (model == null) {
            LOGGER.warn("Model not available, skipping active scan");
            return;
        }

        SiteMap siteTree = model.getSession().getSiteTree();
        if (siteTree == null) {
            LOGGER.warn("Site tree not available, skipping active scan");
            return;
        }

        for (String url : urls) {
            try {
                org.apache.commons.httpclient.URI uri = new org.apache.commons.httpclient.URI(url, true);
                SiteNode node = siteTree.findNode(uri);

                if (node == null) {
                    LOGGER.warn("URL not found in ZAP site tree (was it accessed through the proxy?): {}", url);
                    continue;
                }

                int scanId = ext.startScan(new Target(node));
                LOGGER.info("Started active scan {} for URL: {}", scanId, url);
            } catch (Exception e) {
                LOGGER.error("Failed to start active scan for {}: {}", url, e.getMessage());
            }
        }
    }
}
