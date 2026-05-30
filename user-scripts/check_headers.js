///usr/bin/env jbang

var argsMap = {};
for (var i = 0; i < args.length; i += 2) {
    argsMap[args[i].replace(/^--/, "")] = args[i + 1];
}

var targetUrl = argsMap["target-url"] || "";
var proxyAddr = argsMap["proxy"] || "";
var outputJson = argsMap["output-json"] || "";
var findings = [];

if (!targetUrl) {
    findings.push({
        url: "",
        category: "User Script Finding",
        description: "Missing --target-url argument",
        evidence: "target-url is required"
    });
    writeOutput(findings, outputJson);
} else {
    try {
        var conn = openConnection(targetUrl, proxyAddr);
        conn.setRequestMethod("GET");
        conn.setConnectTimeout(10000);
        conn.setReadTimeout(10000);
        var status = conn.getResponseCode();

        // Check security headers
        var headers = {};
        for (var i = 0;; i++) {
            var key = conn.getHeaderFieldKey(i);
            var val = conn.getHeaderField(i);
            if (key === null && val === null) break;
            if (key !== null) headers[key.toLowerCase()] = val;
        }

        if (!headers["strict-transport-security"]) {
            findings.push({
                url: targetUrl,
                category: "Security Misconfiguration",
                description: "Missing HSTS header",
                evidence: "Strict-Transport-Security header not set"
            });
        }

        if (!headers["content-security-policy"]) {
            findings.push({
                url: targetUrl,
                category: "Security Misconfiguration",
                description: "Missing CSP header",
                evidence: "Content-Security-Policy header not set"
            });
        }

        if (!headers["x-content-type-options"]) {
            findings.push({
                url: targetUrl,
                category: "Security Misconfiguration",
                description: "Missing X-Content-Type-Options header",
                evidence: "X-Content-Type-Options: nosniff not set"
            });
        }

        var server = headers["server"];
        if (server) {
            findings.push({
                url: targetUrl,
                category: "Information Disclosure",
                description: "Server header exposes software version: " + server,
                evidence: "Server: " + server
            });
        }

        var xPoweredBy = headers["x-powered-by"];
        if (xPoweredBy) {
            findings.push({
                url: targetUrl,
                category: "Information Disclosure",
                description: "X-Powered-By header exposes technology: " + xPoweredBy,
                evidence: "X-Powered-By: " + xPoweredBy
            });
        }

        // Redirect check
        if (status >= 300 && status < 400) {
            var location = conn.getHeaderField("Location");
            findings.push({
                url: targetUrl,
                category: "Open Redirect",
                description: "Redirect (" + status + ") to: " + (location || "(none)"),
                evidence: "Location: " + location
            });
        }

    } catch (e) {
        findings.push({
            url: targetUrl,
            category: "User Script Finding",
            description: "Request failed: " + String(e),
            evidence: String(e)
        });
    }
    writeOutput(findings, outputJson);
}

function openConnection(url, proxy) {
    var URL = java.net.URL;
    var endpoint = new URL(url);
    if (!proxy) return endpoint.openConnection();
    var parts = proxy.split(":");
    var Proxy = java.net.Proxy;
    var InetSocketAddress = java.net.InetSocketAddress;
    var p = new Proxy(Proxy.Type.HTTP,
        new InetSocketAddress(parts[0], parseInt(parts[1])));
    return endpoint.openConnection(p);
}

function writeOutput(findings, path) {
    var json = JSON.stringify(findings, null, 2);
    if (path) {
        var Files = java.nio.file.Files;
        var Paths = java.nio.file.Paths;
        Files.writeString(Paths.get(path), json);
    } else {
        console.log(json);
    }
}
