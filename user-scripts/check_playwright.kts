#!/usr/bin/env kotlinc -script
@file:DependsOn("com.microsoft.playwright:playwright:1.59.0")

import com.microsoft.playwright.*
import com.microsoft.playwright.options.Proxy
import java.nio.file.Paths
import kotlin.io.path.writeText

data class Finding(val url: String, val category: String, val description: String, val evidence: String)

fun main() {
    val argsMap = mutableMapOf<String, String>()
    var i = 0
    while (i < this.args.size - 1) {
        argsMap[this.args[i].removePrefix("--")] = this.args[i + 1]
        i += 2
    }

    val targetUrl = argsMap["target-url"] ?: ""
    val proxyAddr = argsMap["proxy"] ?: ""
    val outputJson = argsMap["output-json"] ?: ""
    val findings = mutableListOf<Finding>()

    if (targetUrl.isEmpty()) {
        findings.add(Finding("", "User Script Finding",
            "Missing --target-url argument", "target-url is required"))
        writeOutput(findings, outputJson)
        return
    }

    Playwright.create().use { pw ->
        val launchOpts = BrowserType.LaunchOptions().setHeadless(true)
        if (proxyAddr.isNotEmpty()) {
            launchOpts.setProxy(Proxy(proxyAddr))
        }

        val browser = pw.chromium().launch(launchOpts)
        val context = browser.newContext(Browser.NewContextOptions()
            .setIgnoreHTTPSErrors(true)
            .setUserAgent("Mozilla/5.0 (compatible; ZAP-Playwright-UserScript/1.0)"))
        val page = context.newPage()

        val consoleErrors = mutableListOf<String>()

        page.onConsoleMessage { msg ->
            if (msg.type() == ConsoleMessage.Type.ERROR) {
                consoleErrors.add(msg.text())
            }
        }

        try {
            page.navigate(targetUrl, Page.NavigateOptions()
                .setWaitUntil(Page.WaitUntilState.NETWORKIDLE))

            if (consoleErrors.isNotEmpty()) {
                findings.add(Finding(targetUrl, "Information Disclosure",
                    "Browser console logged ${consoleErrors.size} error(s) during page load",
                    consoleErrors.take(5).joinToString(" | ")))
            }

            val forms = page.querySelectorAll("form")
            for (form in forms) {
                val action = form.getAttribute("action") ?: "(self)"
                val method = (form.getAttribute("method") ?: "get").uppercase()
                if (method == "GET" && form.querySelectorAll("input[type='password']").isNotEmpty()) {
                    findings.add(Finding(targetUrl, "Insecure Design",
                        "Form with password field uses GET method — credentials exposed in URL",
                        "<form method=GET action=$action> with password field"))
                }
            }

        } catch (e: Exception) {
            findings.add(Finding(targetUrl, "User Script Finding",
                "Playwright navigation failed: ${e.message}", e.toString()))
        } finally {
            browser.close()
        }
    }

    writeOutput(findings, outputJson)
}

fun writeOutput(findings: List<Finding>, path: String) {
    val json = buildString {
        append("[\n")
        findings.forEachIndexed { idx, f ->
            append("  {")
            append("\"url\":\"${esc(f.url)}\",")
            append("\"category\":\"${esc(f.category)}\",")
            append("\"description\":\"${esc(f.description)}\",")
            append("\"evidence\":\"${esc(f.evidence)}\"")
            append("}")
            if (idx < findings.size - 1) append(",")
            append("\n")
        }
        append("]")
    }
    if (path.isNotEmpty()) {
        Paths.get(path).writeText(json)
    } else {
        println(json)
    }
}

fun esc(s: String) = s
    .replace("\\", "\\\\")
    .replace("\"", "\\\"")
    .replace("\n", "\\n")
    .replace("\r", "\\r")

main()
