///usr/bin/env jbang
//DEPS com.microsoft.playwright:playwright:1.59.0

import com.microsoft.playwright.*
import com.microsoft.playwright.options.Proxy
import groovy.json.JsonOutput

def argsMap = [:]
for (int i = 0; i < this.args.length; i += 2) {
    argsMap[this.args[i].replaceAll("^--", "")] = this.args[i + 1]
}

def targetUrl = argsMap["target-url"]
def proxyAddr = argsMap["proxy"]
def outputJson = argsMap["output-json"]
def findings = []

if (!targetUrl) {
    findings << [url: "", category: "User Script Finding",
                 description: "Missing --target-url argument", evidence: "target-url is required"]
    writeOutput(findings, outputJson)
    return
}

try {
    Playwright playwright = Playwright.create()
    try {
        def launchOpts = new BrowserType.LaunchOptions().setHeadless(true)
        if (proxyAddr) {
            launchOpts.setProxy(new Proxy(proxyAddr))
        }

        def browser = playwright.chromium().launch(launchOpts)
        try {
            def context = browser.newContext(
                new Browser.NewContextOptions()
                    .setIgnoreHTTPSErrors(true)
                    .setUserAgent("Mozilla/5.0 (compatible; ZAP-Playwright-UserScript/1.0)"))
            def page = context.newPage()

            def consoleErrors = []

            page.onConsoleMessage { msg ->
                if (msg.type() == ConsoleMessage.Type.ERROR) {
                    consoleErrors << msg.text()
                }
            }

            page.onPageError { err ->
                findings << [url: targetUrl, category: "DOMXSS Advanced",
                             description: "Uncaught JS exception: ${err.toString().substring(0, 200)}",
                             evidence: err.toString()]
            }

            page.navigate(targetUrl,
                new Page.NavigateOptions().setWaitUntil(Page.WaitUntilState.NETWORKIDLE))

            if (consoleErrors) {
                def top5 = consoleErrors.size() > 5 ? consoleErrors[0..4] : consoleErrors
                findings << [url: targetUrl, category: "Information Disclosure",
                             description: "Browser console logged ${consoleErrors.size()} error(s)",
                             evidence: top5.join(" | ")]
            }

            def scripts = page.$$("script[src]")
            def noSRI = scripts.findAll { script ->
                !script.getAttribute("integrity")
            }
            if (noSRI) {
                def top3 = noSRI.size() > 3 ? noSRI[0..2] : noSRI
                findings << [url: targetUrl, category: "Missing SRI",
                             description: "${noSRI.size()} external script(s) without Subresource Integrity",
                             evidence: top3.collect { it.getAttribute("src") }.join(" | ")]
            }

        } finally {
            browser.close()
        }
    } finally {
        playwright.close()
    }
} catch (Exception e) {
    findings << [url: targetUrl, category: "User Script Finding",
                 description: "Playwright error: ${e.message}", evidence: e.toString()]
}

writeOutput(findings, outputJson)

void writeOutput(List<Map> findings, String outputPath) {
    def json = JsonOutput.prettyPrint(JsonOutput.toJson(findings))
    if (outputPath) {
        new File(outputPath).text = json
    } else {
        println json
    }
}
