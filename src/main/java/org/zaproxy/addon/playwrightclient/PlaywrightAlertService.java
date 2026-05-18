package org.zaproxy.addon.playwrightclient;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PlaywrightAlertService {

    private static final Logger LOGGER = LoggerFactory.getLogger(PlaywrightAlertService.class);

    public PlaywrightAlertService() {
    }

    public void createAlert(String url, String evidence) {
        // Avoid ZAP Alert API coupling at compile time in this environment; log for now.
        LOGGER.info("[PlaywrightAlertService] {} evidence: {}", url, evidence);
    }
}
