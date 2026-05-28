package org.zaproxy.addon.playwrightclient;

import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.api.*;
import net.sf.json.JSONObject;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Comparator;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PlaywrightClientApi extends ApiImplementor {

    private static final Logger LOGGER = LoggerFactory.getLogger(PlaywrightClientApi.class);

    private static final String PREFIX = "playwrightclient";
    private static final String ACTION_RUN = "runCrawlAndScan";
    private static final String ACTION_SCREENSHOT = "screenshotPage";
    private static final String OTHER_SCREENSHOT = "screenshot";

    private final ExtensionPlaywrightClient ext;

    public PlaywrightClientApi(ExtensionPlaywrightClient ext) {
        this.ext = ext;

        this.addApiAction(new ApiAction(ACTION_RUN, new String[]{"url"}));
        this.addApiAction(new ApiAction(ACTION_SCREENSHOT, new String[]{"url"}));
        this.addApiOthers(new ApiOther(OTHER_SCREENSHOT, new String[0], new String[]{"file", "url"}));
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
                return handleError(t);
            }
        }

        if (ACTION_SCREENSHOT.equals(name)) {
            String url = params.getString("url");
            try {
                Path path = ext.takeScreenshot(url);
                return new ApiResponseElement("result", path.toAbsolutePath().toString());
            } catch (Throwable t) {
                return handleError(t);
            }
        }

        throw new ApiException(ApiException.Type.BAD_ACTION);
    }

    private ApiResponse handleError(Throwable t) throws ApiException {
        LOGGER.error("API action failed", t);
        t.printStackTrace(System.err);

        try {
            String ws = System.getProperty("java.io.tmpdir", ".");
            ws = ws.replace("\"", "").trim();
            File dir = new File(ws);
            if (!dir.isAbsolute()) {
                dir = new File(System.getProperty("user.dir", "."), ws);
            }
            dir.mkdirs();
            File out = new File(dir, "playwrightclient-error.log");
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

    @Override
    public HttpMessage handleApiOther(HttpMessage msg, String name, JSONObject params) throws ApiException {
        if (OTHER_SCREENSHOT.equals(name)) {
            Path dir = ext.getScreenshotDir();
            String fileParam = params.optString("file", null);

            if (fileParam != null && !fileParam.isEmpty()) {
                File target = dir.resolve(fileParam).toFile();
                if (!target.exists()) {
                    throw new ApiException(ApiException.Type.DOES_NOT_EXIST, "Screenshot not found: " + fileParam);
                }
                return serveFile(msg, target);
            }

            File[] files = dir.toFile().listFiles((d, f) -> f.endsWith(".png"));
            if (files == null || files.length == 0) {
                throw new ApiException(ApiException.Type.DOES_NOT_EXIST, "No screenshots found");
            }

            File latest = Arrays.stream(files)
                .max(Comparator.comparingLong(File::lastModified))
                .orElseThrow(() -> new ApiException(ApiException.Type.DOES_NOT_EXIST, "No screenshots found"));

            return serveFile(msg, latest);
        }

        throw new ApiException(ApiException.Type.BAD_OTHER);
    }

    private HttpMessage serveFile(HttpMessage msg, File file) throws ApiException {
        try {
            byte[] bytes = Files.readAllBytes(file.toPath());
            msg.setResponseBody(bytes);
            try {
                msg.setResponseHeader(
                        API.getDefaultResponseHeader("image/png", bytes.length));
            } catch (HttpMalformedHeaderException e) {
                LOGGER.error("Failed to create response header: {}", e.getMessage(), e);
                throw new ApiException(ApiException.Type.INTERNAL_ERROR, e.getMessage());
            }
        } catch (IOException e) {
            LOGGER.error("Failed to serve screenshot", e);
            throw new ApiException(ApiException.Type.INTERNAL_ERROR, e.getMessage());
        }
        return msg;
    }
}
