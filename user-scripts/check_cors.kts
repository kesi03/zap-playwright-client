#!/usr/bin/env kotlinc -script
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.file.Files
import java.nio.file.Paths
import kotlin.io.path.writeText

data class Finding(val url: String, val category: String, val description: String, val evidence: String)

fun main() {
    val argsMap = mutableMapOf<String, String>()
    var i = 0
    while (i < args.size - 1) {
        argsMap[args[i].removePrefix("--")] = args[i + 1]
        i += 2
    }

    val targetUrl = argsMap["target-url"] ?: ""
    val outputJson = argsMap["output-json"] ?: ""
    val findings = mutableListOf<Finding>()

    if (targetUrl.isEmpty()) {
        findings.add(Finding("", "User Script Finding",
            "Missing --target-url argument", "target-url is required"))
        writeOutput(findings, outputJson)
        return
    }

    try {
        val client = HttpClient.newBuilder()
            .connectTimeout(java.time.Duration.ofSeconds(10))
            .build()

        val origin = URI(targetUrl).let { "${it.scheme}://${it.host}" }

        val request = HttpRequest.newBuilder()
            .uri(URI.create(targetUrl))
            .header("Origin", "https://evil.com")
            .method("GET", HttpRequest.BodyPublishers.noBody())
            .build()

        val response = client.send(request, HttpResponse.BodyHandlers.ofString())
        val acao = response.headers().firstValue("access-control-allow-origin").orElse("")

        val acac = response.headers().firstValue("access-control-allow-credentials").orElse("")

        if (acao == "*") {
            findings.add(Finding(targetUrl, "CORS Misconfig",
                "Server allows all origins (ACAO: *) — any website can read resources",
                "Access-Control-Allow-Origin: *"))
        }

        if (acao == "https://evil.com" || acao.contains("evil")) {
            findings.add(Finding(targetUrl, "CORS Misconfig",
                "Server reflects Origin header without validation",
                "Access-Control-Allow-Origin: $acao"))
        }

        if (acao == "*" && acac == "true") {
            findings.add(Finding(targetUrl, "CORS Misconfig",
                "Wildcard origin with credentials enabled — dangerous combination",
                "ACAO: *, ACAC: true"))
        }

        if (!acao.isNullOrEmpty() && response.statusCode() in 200..299) {
            findings.add(Finding(targetUrl, "CORS Misconfig",
                "CORS allows cross-origin access from evil.com with status ${response.statusCode()}",
                "Origin: https://evil.com → ACAO: $acao"))
        }

    } catch (e: Exception) {
        findings.add(Finding(targetUrl, "User Script Finding",
            "Script error: ${e.message}", e.toString()))
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
