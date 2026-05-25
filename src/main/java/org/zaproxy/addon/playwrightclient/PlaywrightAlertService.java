package org.zaproxy.addon.playwrightclient;

import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.SiteMap;
import org.parosproxy.paros.model.SiteNode;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.addon.playwrightclient.owasp.OwaspTestFinding;
import org.zaproxy.zap.extension.alert.ExtensionAlert;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PlaywrightAlertService {

    private static final Logger LOGGER = LoggerFactory.getLogger(PlaywrightAlertService.class);

    private static final int PLUGIN_ID = 60101;

    private final ExtensionAlert extAlert;
    private final SiteMap siteTree;

    public PlaywrightAlertService() {
        ExtensionAlert ea = null;
        SiteMap st = null;
        try {
            Model model = Model.getSingleton();
            ea = Control.getSingleton()
                .getExtensionLoader()
                .getExtension(ExtensionAlert.class);
            if (model.getSession() != null) {
                st = model.getSession().getSiteTree();
            }
        } catch (Exception ignored) {}
        this.extAlert = ea;
        this.siteTree = st;
    }

    public void createAlert(OwaspTestFinding finding) {
        if (extAlert == null) {
            LOGGER.warn("ExtensionAlert not available, cannot create alert");
            return;
        }

        try {
            String url = (finding.url != null && !finding.url.isEmpty()) ? finding.url : "";
            String evidence = finding.evidence != null ? finding.evidence : finding.description;
            String description = finding.description != null ? finding.description : evidence;
            int risk = mapRisk(finding.category);
            String alertName = "Playwright: " + (finding.category != null ? finding.category : "Security Finding");

            HttpMessage alertMsg = new HttpMessage();
            alertMsg.setRequestHeader(new HttpRequestHeader("GET " + url + " HTTP/1.1"));
            alertMsg.getResponseHeader().setStatusCode(200);
            Alert alert = new Alert(PLUGIN_ID);
            alert.setDetail(
                alertName,
                description,
                url,
                "",
                "",
                "",
                "",
                "",
                risk,
                Alert.CONFIDENCE_MEDIUM,
                alertMsg);
            alert.setSource(Alert.Source.TOOL);
            alert.setCweId(mapCwe(finding.category));
            alert.setWascId(mapWasc(finding.category));
            alert.setEvidence(evidence);

            HistoryReference hRef = findHistoryRef(url);
            if (hRef == null) {
                LOGGER.warn("No history entry found for {}, creating alert without history ref", url);
                HttpMessage msg = new HttpMessage();
                msg.setRequestHeader(new HttpRequestHeader("GET " + url + " HTTP/1.1"));
                msg.getResponseHeader().setStatusCode(200);
                hRef = new HistoryReference(
                    Model.getSingleton().getSession(),
                    HistoryReference.TYPE_SCANNER_TEMPORARY,
                    msg);
            }

            extAlert.alertFound(alert, hRef);
            LOGGER.info("Created ZAP alert for {}: [{}] {}", url, finding.category, evidence);
        } catch (Exception e) {
            LOGGER.error("Failed to create alert: {}", e.getMessage(), e);
        }
    }

    private HistoryReference findHistoryRef(String url) {
        if (siteTree == null || url == null || url.isEmpty()) return null;
        try {
            org.apache.commons.httpclient.URI uri = new org.apache.commons.httpclient.URI(url, true);
            SiteNode node = siteTree.findNode(uri);
            if (node != null) {
                HistoryReference hRef = node.getHistoryReference();
                if (hRef != null) return hRef;
                java.util.Vector<HistoryReference> pastRefs = node.getPastHistoryReference();
                if (pastRefs != null && !pastRefs.isEmpty()) return pastRefs.get(0);
            }
        } catch (Exception ignored) {}
        return null;
    }

    private static int mapRisk(String category) {
        if (category == null) return Alert.RISK_MEDIUM;
        String c = category.toLowerCase();
        if (c.contains("xss") || c.contains("injection") || c.contains("broken access")
            || c.contains("auth") || c.contains("ssrf") || c.contains("path traversal")) {
            return Alert.RISK_HIGH;
        }
        if (c.contains("crypto") || c.contains("security misconfig") || c.contains("cors")
            || c.contains("clickjack") || c.contains("open redirect") || c.contains("csp")) {
            return Alert.RISK_MEDIUM;
        }
        return Alert.RISK_MEDIUM;
    }

    private static int mapCwe(String category) {
        if (category == null) return 0;
        String c = category.toLowerCase();
        if (c.contains("xss")) return 79;
        if (c.contains("broken access")) return 862;
        if (c.contains("crypto") || c.contains("cryptographic")) return 327;
        if (c.contains("injection")) return 94;
        if (c.contains("clickjack")) return 1021;
        if (c.contains("open redirect")) return 601;
        if (c.contains("ssrf")) return 918;
        if (c.contains("path traversal")) return 22;
        return 0;
    }

    private static int mapWasc(String category) {
        if (category == null) return 0;
        String c = category.toLowerCase();
        if (c.contains("xss")) return 8;
        if (c.contains("injection")) return 19;
        if (c.contains("broken access")) return 2;
        if (c.contains("auth")) return 1;
        if (c.contains("ssrf")) return 20;
        return 0;
    }
}
