#!/usr/bin/env groovy
import groovy.json.JsonOutput

def args = [:]
for (int i = 0; i < this.args.length; i += 2) {
    def key = this.args[i].replaceAll("^--", "")
    args[key] = this.args[i + 1]
}

def targetUrl = args["target-url"]
def outputJson = args["output-json"]
def findings = []

if (!targetUrl) {
    findings << [url: "", category: "User Script Finding",
                 description: "Missing --target-url argument", evidence: "target-url is required"]
    writeOutput(findings, outputJson)
    return
}

try {
    def url = new URL(targetUrl)
    def connection = url.openConnection()
    connection.setRequestMethod("GET")
    connection.connectTimeout = 10000
    connection.readTimeout = 10000

    def responseCode = connection.responseCode
    def headers = connection.headerFields

    def setCookie = headers.get("Set-Cookie")
    if (setCookie) {
        setCookie.each { cookie ->
            if (cookie.toLowerCase().contains("httponly")) {
                if (!cookie.toLowerCase().contains("secure")) {
                    findings << [url: targetUrl, category: "Security Misconfiguration",
                                 description: "Cookie missing Secure flag: " + cookie.split(";")[0],
                                 evidence: "Set-Cookie: " + cookie]
                }
            } else {
                findings << [url: targetUrl, category: "Security Misconfiguration",
                             description: "Cookie missing HttpOnly flag: " + cookie.split(";")[0],
                             evidence: "Set-Cookie: " + cookie]
            }
        }
    }

    if (responseCode >= 200) {
        def body = connection.inputStream.text
        def emailPattern = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/
        def emails = (body =~ emailPattern).findAll().unique()
        if (emails.size() > 0 && emails.size() < 5) {
            findings << [url: targetUrl, category: "Information Disclosure",
                         description: "Found ${emails.size()} email address(es) in page content",
                         evidence: "Emails: ${emails.join(', ')}"]
        }
    }

} catch (Exception e) {
    findings << [url: targetUrl, category: "User Script Finding",
                 description: "Script error: ${e.message}", evidence: e.toString()]
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
