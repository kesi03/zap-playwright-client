package org.zaproxy.addon.playwrightclient;

import org.parosproxy.paros.control.Control;
import org.zaproxy.zap.extension.ascan.ExtensionActiveScan;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Set;

public class ZapScanOrchestrator {

    private static final Logger LOGGER = LoggerFactory.getLogger(ZapScanOrchestrator.class);

    private final ExtensionActiveScan ext;

    public ZapScanOrchestrator() {
        ExtensionActiveScan e = null;
        try {
            e = Control.getSingleton()
                .getExtensionLoader()
                .getExtension(ExtensionActiveScan.class);
        } catch (Exception ignored) {}
        this.ext = e;
    }

    public void scanUrls(Set<String> urls) {
        // Be conservative: if the active scan extension isn't available, just log
        if (ext == null) {
            for (String u : urls) {
                LOGGER.info("[ZapScanOrchestrator] URL: {}", u);
            }
            return;
        }

        for (String url : urls) {
            try {
                // Use existing ExtensionActiveScan APIs in runtime — being conservative here
                LOGGER.info("[ZapScanOrchestrator] would scan: {}", url);
            } catch (Exception ignored) {}
        }
    }
}
