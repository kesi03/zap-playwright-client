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
        LOGGER.info("handleApiAction called: {} with params: {}", name, params == null ? "null" : params.toString());

        if (ACTION_RUN.equals(name)) {
            String url = params.getString("url");
            try {
                ext.runCrawlAndScan(url);
                return new ApiResponseElement("result", "started");
            } catch (Throwable t) {
                // Log via SLF4J
                LOGGER.error("API action runCrawlAndScan failed", t);
                // Also print to stderr to ensure CI captures it (some runners capture stderr separately)
                t.printStackTrace(System.err);

                // Attempt to write stacktrace to a temp file inside ZAP workspace if possible
                try {
                    String tmp = System.getProperty("java.io.tmpdir");
                    java.io.File out = new java.io.File(tmp, "playwrightclient-error.log");
                    try (java.io.PrintWriter pw = new java.io.PrintWriter(new java.io.FileWriter(out, true))) {
                        pw.println("--- PlaywrightClientApi error at " + new java.util.Date() + " ---");
                        t.printStackTrace(pw);
                        pw.println();
                    }
                    LOGGER.info("Wrote error stacktrace to {}", out.getAbsolutePath());
                } catch (Exception writeEx) {
                    LOGGER.warn("Failed to write stacktrace to temp file", writeEx);
                }

                throw new ApiException(ApiException.Type.INTERNAL_ERROR, t.getMessage());
            }
        }

        throw new ApiException(ApiException.Type.BAD_ACTION);
    }
}
