package org.zaproxy.addon.playwrightclient;

import org.zaproxy.zap.extension.api.*;
import org.json.JSONObject;

public class PlaywrightClientApi extends ApiImplementor {

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

    public ApiResponse handleApiAction(String name, JSONObject params) throws ApiException {
        if (ACTION_RUN.equals(name)) {
            String url = params.getString("url");
            ext.runCrawlAndScan(url);
            return new ApiResponseElement("result", "started");
        }

        throw new ApiException(ApiException.Type.BAD_ACTION);
    }
}
