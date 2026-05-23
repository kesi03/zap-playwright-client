package org.zaproxy.addon.playwrightclient;

import org.zaproxy.zap.extension.api.*;
import net.sf.json.JSONObject;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PlaywrightClientApi extends ApiImplementor {

    private static final Logger LOGGER = LoggerFactory.getLogger(PlaywrightClientApi.class);

    private static final String PREFIX = "playwrightclient";
    private static final String ACTION_RUN = "runCrawlAndScan";

    private final ExtensionPlaywrightClient ext;

    public PlaywrightClientApi(ExtensionPlaywrightClient ext) {
        this.ext = ext;

        this.addApiAction(new ApiAction(ACTION_RUN, new String[]{"url"}));
    }

    public String getPrefix() {
        return PREFIX;
    }

    @Override
    public ApiResponse handleApiAction(String name, JSONObject params) throws ApiException {
        if (ACTION_RUN.equals(name)) {
            String url = params.getString("url");
            try {
                ext.runCrawlAndScan(url);
                return new ApiResponseElement("result", "started");
            } catch (Exception e) {
                LOGGER.error("API action runCrawlAndScan failed", e);
                throw new ApiException(ApiException.Type.INTERNAL_ERROR, e.getMessage());
            }
        }

        throw new ApiException(ApiException.Type.BAD_ACTION);
    }
}
