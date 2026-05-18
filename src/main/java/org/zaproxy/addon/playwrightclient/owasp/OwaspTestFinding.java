package org.zaproxy.addon.playwrightclient.owasp;

public class OwaspTestFinding {
    public final String category;
    public final String description;
    public final String url;
    public final String evidence;

    public OwaspTestFinding(String category, String description, String url, String evidence) {
        this.category = category;
        this.description = description;
        this.url = url;
        this.evidence = evidence;
    }
}
