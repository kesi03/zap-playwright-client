# 🛡️ **PlaywrightClient Add-on — OWASP Browser-Side Security Test Suite**

The **PlaywrightClient** add-on extends OWASP ZAP with a modern, browser-powered security testing engine.  
It uses **Playwright** to execute your application in a real browser, detect client-side vulnerabilities, and feed findings directly into ZAP as alerts.

This complements ZAP's traditional passive and active scanning by adding **SPA-aware, DOM-aware, JavaScript-aware** security checks that ZAP alone cannot perform.

---

# 🚀 **Quick Start**

## Prerequisites

- Node.js 18+
- Java JDK 21

## Install Dependencies

```bash
npm install
```

## Build and Run (Full Workflow)

The following command builds the add-on, downloads/packs ZAP, installs the add-on, and starts the ZAP daemon:

```bash
npm run dev
```

This executes `scripts/dev.ts` which:
1. Builds the Gradle add-on (`gradlew build`)
2. Creates an offline ZAP package (if not already unpacked)
3. Unpacks ZAP into `zap-dev-install/`
4. Installs the built `.zap` file into ZAP's plugin directory
5. Patches ZAP's TOML config for ZGC compatibility
6. Starts the ZAP daemon on `http://127.0.0.1:8080`

## Running Integration Tests

After the daemon is running, execute the full integration test suite:

```bash
npm run test:integration
```

This runs `scripts/integration.ts` which:
1. Connects to the ZAP daemon (starts it via `npm run dev` if not running)
2. Calls the `playwrightclient/runCrawlAndScan` API against a target URL
3. Monitors ZAP logs for Playwright-generated alerts
4. Cross-checks alerts via the ZAP API
5. Exits with code 0 on success, 1 on failure

## Running the Screenshot Test

```bash
npm run test:photo
```

This runs `scripts/photo.ts` which:
1. Connects to ZAP (starts via `npm run dev` if needed)
2. Takes a screenshot of a target URL via `playwrightclient/screenshotPage`
3. Downloads the PNG via `playwrightclient/other/screenshot`
4. Validates the PNG file integrity
5. Exits with code 0 on success, 1 on failure

---

# 📌 **What This Add-on Does**

When you run the PlaywrightClient:

1. It launches a real Chromium browser through ZAP's proxy  
2. Crawls the target application (React, Angular, Vue, SPA, MPA — all supported) using a BFS SPA-aware crawler  
3. Runs **61 OWASP browser-side tests**  
4. Converts findings into ZAP alerts with CWE/WASC mappings and appropriate risk levels  
5. Triggers ZAP's active scanner on all discovered URLs (including AJAX API endpoints intercepted during testing)  

This gives you **full-stack coverage**:

- ZAP passive scan  
- ZAP active scan  
- Playwright browser-side OWASP tests  

---

# 🧪 **OWASP Browser-Side Tests Included**

Below is a complete list of all **61** tests the suite performs, grouped by OWASP category.

---

## 🔐 **A01 — Broken Access Control**
- Accessing sensitive routes without authentication (`/admin`, `/settings`, `/internal`)
- Open redirect detection (`redirect=`, `next=`, `returnUrl=`)
- Weak password reset flow (missing email verification)
- CSRF — session cookie missing `SameSite` attribute
- Tabnabbing — `target="_blank"` links missing `rel="noopener noreferrer"`
- Unsafe HTTP methods (DELETE, PUT, PATCH) detected in requests

---

## 🔑 **A02 — Cryptographic Failures**
- Cookies missing `Secure`, `HttpOnly`, or `SameSite`
- Mixed content (HTTP resources on HTTPS pages)
- Missing HSTS header
- Sensitive data stored in `localStorage` or `sessionStorage`
- Hardcoded credentials in page content (`password`, `secret`, `apikey`, `token`)
- JWT decoding performed client-side (`jwt.decode`, `atob`)
- Insecure WebSocket usage (`ws://` instead of `wss://`)
- Exposed environment variables (`process.env`)
- Sensitive data keywords in JavaScript (`apiKey`, `secret`, `token`)
- Autocomplete enabled on sensitive fields (password, credit card)
- Canvas `toDataURL()` / `toBlob()` — possible client-side data exfiltration
- Fonts loaded over unencrypted HTTP
- Images loaded over HTTP (mixed content via AJAX/DOM)

---

## 🧨 **A03 — Injection**
- DOM-based XSS detection (script injection, event handlers)
- Advanced DOM XSS (inline `onerror`, `onload` handlers)
- Reflected parameter injection (`?q=payload`)
- Dangerous JS functions (`eval`, `new Function`)
- Prototype pollution indicators (`__proto__`)
- DOM clobbering (`window["constructor"]`, `document["__proto__"]`)
- Client-side path traversal (`/static/../etc/passwd`)
- `innerHTML` / `document.write()` usage — possible DOM XSS vector
- `document.domain` lowered — weakens same-origin policy
- Form inputs missing pattern validation — potential script injection vector
- Insecure SVG detection (`<script>` in SVG, event handlers, `<foreignObject>`, external `<use>` references)
- Image security: event handlers on `<img>` tags (XSS vector)

---

## 🏗️ **A04 — Insecure Design**
- Weak password policy (accepting trivial passwords like `123`)
- Missing validation on sensitive fields
- SPA route table enumeration (`window.__ROUTES__` leak)
- Login forms missing anti-CSRF tokens
- Text inputs/textarea missing maxlength or pattern limits
- AJAX call interception — discovers API endpoints, detects internal API calls, sensitive data in request bodies, and HTTP-based AJAX
- Missing `crossorigin` on external fonts — font fingerprinting/tracking risk
- Tracking pixels / `navigator.sendBeacon()` — possible data exfiltration
- Inline base64 images — review for sensitive data exposure

---

## 📦 **A05 — Security Misconfiguration**
- Missing or weak CSP (`unsafe-inline`, `unsafe-eval`)
- CSP nonce reuse
- Missing X-Frame-Options / frame-ancestors (clickjacking)
- Missing X-Content-Type-Options (`nosniff`) header
- Missing Permissions-Policy header
- Missing Cache-Control header
- Weak iframe sandboxing
- CORS misconfiguration (`Access-Control-Allow-Origin: *`)
- Weak CORS preflight (permissive methods with wildcard origin)
- Exposed environment variables (`process.env`)
- Insecure third-party widget loading
- Insecure file upload (`accept="*"`)
- GraphQL introspection query probing (`/graphql`)

---

## 🧬 **A06 — Vulnerable & Outdated Components**
- React DevTools hook present in production
- React version leaked to the client
- React hydration errors (console monitoring)
- OAuth misconfiguration (`client_secret` or `clientId` in client-side code)
- Known JavaScript library detection (jQuery, Angular, Vue, React, Backbone, Underscore, Moment, SocketIO, Bootstrap)
- Npm-based framework detection (webpack, Next.js, Nuxt, Vue CLI, Sentry, GA, GTM, FB Pixel)
- Source map exposure detection (`/node_modules/` references in page source)

---

## 🔐 **A07 — Identification & Authentication Failures**
- Login page missing password field
- Login form submits credentials over HTTP
- OAuth implicit flow detected (`access_token` in URL fragment)

---

## 🧱 **A08 — Software & Data Integrity Failures**
- Insecure script loading (`http://cdn...`)
- postMessage listener potentially lacking origin validation
- External scripts loaded without SRI `integrity` attribute
- Service Worker active (potential caching of sensitive data)

---

## 📉 **A09 — Security Logging & Monitoring Failures**
- JavaScript console errors detected during browsing

---

## 🌐 **A10 — Server-Side Request Forgery Indicators**
- Client-side fetch calls to internal metadata endpoints  
  (`169.254.*`, `metadata.google.internal`, `localhost`)

---

# 📸 **Screenshot Functionality**

The add-on provides a full screenshot capability for visual inspection of target pages:

## API Endpoints

| Endpoint | Type | Parameters | Description |
|---|---|---|---|
| `playwrightclient/action/screenshotPage` | action | `url` | Takes a PNG screenshot of the given URL, returns the file path |
| `playwrightclient/other/screenshot` | other | `file` (optional) | Serves a screenshot PNG. If `file` is given, serves that specific file; otherwise serves the most recent PNG |

Screenshots are saved to `$ZAP_HOME/screenshots/` with filenames like `{sanitizedUrl}_{yyyyMMdd_HHmmss}.png`.

---

# 🧭 **SPA / React / Modern Frontend Tests**
These tests are specifically designed for modern JavaScript applications:

- SPA route enumeration (React Router route leaks via `window.__ROUTES__`)
- Detection of client-side routing tables
- React hydration / devtools exposure
- Dynamic DOM scanning after navigation
- Event-driven DOM mutation checks

---

# 🧰 **Additional Browser Security Checks**
- Autocomplete enabled on sensitive fields (password, credit card)
- Insecure file upload (`accept="*"`)
- Inline script detection
- Suspicious inline event handlers (`onerror`, `onload`)
- Exposed API keys in JS bundles
- GraphQL introspection probing

---

# 📊 **How Results Are Reported**

Each finding is converted into a ZAP alert with:

- **URL**  
- **Description**  
- **Evidence**  
- **OWASP category**  
- **Risk level** (mapped by category — HIGH for XSS/injection/broken access, MEDIUM for crypto/misconfig)  
- **CWE and WASC IDs**  
- **Plugin ID 60101**

Alerts appear in:

- ZAP Alerts tab  
- ZAP reports  
- Automation Framework output  
- API responses  

---

# 🚀 **How It Fits Into ZAP**

The PlaywrightClient add-on works alongside:

- ZAP Spider  
- ZAP AJAX Spider (optional)  
- ZAP Passive Scanner  
- ZAP Active Scanner  

It adds **browser-side intelligence** that ZAP's core engine cannot provide.

---

# 🧩 **Ideal Use Cases**

- Testing **React / Angular / Vue** apps  
- Testing **SPAs** with dynamic routing  
- Detecting **DOM-based vulnerabilities**  
- Detecting **client-side misconfigurations**  
- Strengthening **CI/CD pipelines**  
- Enhancing **ZAP Automation Framework** scans  

---

# 🏁 **Summary**

The PlaywrightClient add-on transforms ZAP into a **full browser-aware security scanner**, capable of detecting modern client-side vulnerabilities that traditional scanners miss.

It provides:

- A real browser  
- A full OWASP test suite (61 tests)  
- SPA-aware crawling  
- Automatic ZAP alert creation with CWE/WASC mappings  
- Screenshot capture and retrieval  
- Seamless integration with ZAP's scanning engine  

---

# 🛠 **Development Workflow (Taskfile)**

A `Taskfile.yml` is provided for development automation:

| Task | Description |
|---|---|
| `default` | Full workflow: build, offline-pack, offline-unpack, install-addon, patch-toml, start-daemon |
| `build-addon` | Run `gradlew build` |
| `offline-pack` | Create offline ZAP tar |
| `offline-unpack` | Unpack ZAP to `zap-dev-install/` |
| `install-addon` | Copy built `.zap` into ZAP's plugin directory |
| `patch-toml` | Patch `default.toml` for ZGC compatibility |
| `start-daemon` | Start ZAP daemon |

---

# 📦 **Available npm Scripts**

| Script | Command | Description |
|---|---|---|
| `npm run dev` | `scripts/dev.ts` | Build add-on, unpack ZAP, install plugin, start daemon |
| `npm run test:integration` | `scripts/integration.ts` | Run full crawl + scan integration test |
| `npm run test:photo` | `scripts/photo.ts` | Run screenshot capture and validation test |
| `npm run install:chrome` | Playwright CLI | Install Chromium browser for Playwright |
| `npm run doctor` | Playwright CLI | Check Playwright browser installation |
