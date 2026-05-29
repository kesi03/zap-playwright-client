package org.zaproxy.addon.playwrightclient.automation;

import java.util.LinkedHashMap;
import java.util.Map;
import org.parosproxy.paros.control.Control;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.zaproxy.addon.automation.AutomationEnvironment;
import org.zaproxy.addon.automation.AutomationJob;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.addon.automation.jobs.JobUtils;
import org.zaproxy.addon.playwrightclient.ExtensionPlaywrightClient;

public class PlaywrightJob extends AutomationJob {

    public static final String JOB_NAME = "playwright";
    private static final Logger LOGGER = LoggerFactory.getLogger(PlaywrightJob.class);

    private Parameters parameters = new Parameters();

    public PlaywrightJob() {}

    @Override
    public void verifyParameters(AutomationProgress progress) {
        Map<?, ?> jobData = this.getJobData();
        if (jobData != null) {
            JobUtils.applyParamsToObject(
                    (LinkedHashMap<?, ?>) jobData.get("parameters"),
                    this.parameters,
                    this.getName(),
                    null,
                    progress);
        }
    }

    @Override
    public void applyParameters(AutomationProgress progress) {}

    @Override
    public void runJob(AutomationEnvironment env, AutomationProgress progress) {
        String url = parameters.getUrl();
        if (url == null || url.isEmpty()) {
            progress.error("The 'url' parameter is required for the playwright job.");
            return;
        }
        url = env.replaceVars(url);

        String driverDir = parameters.getDriverDir();
        if (driverDir != null && !driverDir.isEmpty()) {
            driverDir = env.replaceVars(driverDir);
            progress.info("Playwright: setting driver directory to " + driverDir);
            System.setProperty("playwright.cli.dir", driverDir);
        }

        String scriptsDir = parameters.getScriptsDir();
        if (scriptsDir != null && !scriptsDir.isEmpty()) {
            scriptsDir = env.replaceVars(scriptsDir);
            progress.info("Playwright: user scripts directory: " + scriptsDir);
        }

        ExtensionPlaywrightClient ext =
                Control.getSingleton()
                        .getExtensionLoader()
                        .getExtension(ExtensionPlaywrightClient.class);

        if (ext == null) {
            progress.error("ExtensionPlaywrightClient not found.");
            return;
        }

        progress.info("Playwright: starting crawl and scan for " + url);
        try {
            ext.runCrawlAndScan(url, scriptsDir);
            progress.info("Playwright: crawl and scan complete for " + url);
        } catch (Exception e) {
            LOGGER.error("Playwright job failed: {}", e.getMessage(), e);
            progress.error("Playwright job failed: " + e.getMessage());
        }
    }

    @Override
    public String getType() {
        return JOB_NAME;
    }

    @Override
    public Order getOrder() {
        return Order.AFTER_EXPLORE;
    }

    @Override
    public Object getParamMethodObject() {
        return null;
    }

    @Override
    public String getParamMethodName() {
        return null;
    }

    @Override
    public String getSummary() {
        return "Runs Playwright browser-side OWASP tests against the target.";
    }

    @Override
    public String getTemplateDataMin() {
        return loadResource(getType() + "-min.yaml");
    }

    @Override
    public String getTemplateDataMax() {
        return loadResource(getType() + "-max.yaml");
    }

    private String loadResource(String name) {
        try (java.io.InputStream in = getClass().getResourceAsStream(name)) {
            if (in != null) {
                return new String(in.readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
            }
        } catch (Exception e) {
            LOGGER.warn("Failed to load resource: {}", name, e);
        }
        return "";
    }

    @Override
    public AutomationJob newJob() {
        return new PlaywrightJob();
    }

    public static class Parameters {
        private String url;
        private int maxDepth = 5;
        private int maxDuration = 10;
        private String driverDir;
        private String scriptsDir;

        public String getUrl() {
            return url;
        }

        public void setUrl(String url) {
            this.url = url;
        }

        public int getMaxDepth() {
            return maxDepth;
        }

        public void setMaxDepth(int maxDepth) {
            this.maxDepth = maxDepth;
        }

        public int getMaxDuration() {
            return maxDuration;
        }

        public void setMaxDuration(int maxDuration) {
            this.maxDuration = maxDuration;
        }

        public String getDriverDir() {
            return driverDir;
        }

        public void setDriverDir(String driverDir) {
            this.driverDir = driverDir;
        }

        public String getScriptsDir() {
            return scriptsDir;
        }

        public void setScriptsDir(String scriptsDir) {
            this.scriptsDir = scriptsDir;
        }
    }
}
