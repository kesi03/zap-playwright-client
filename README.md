# 🛡️ **PlaywrightClient Add-on — OWASP Browser‑Side Security Test Suite**

The **PlaywrightClient** add-on extends OWASP ZAP with a modern, browser‑powered security testing engine.  
It uses **Playwright** to execute your application in a real browser, detect client‑side vulnerabilities, and feed findings directly into ZAP as alerts.

This complements ZAP’s traditional passive and active scanning by adding **SPA‑aware, DOM‑aware, JavaScript‑aware** security checks that ZAP alone cannot perform.

---

# 📌 **What This Add-on Does**

When you run the PlaywrightClient:

1. It launches a real Chromium browser through ZAP’s proxy  
2. Crawls the target application (React, Angular, Vue, SPA, MPA — all supported)  
3. Runs **40+ OWASP browser‑side tests**  
4. Converts findings into ZAP alerts  
5. Triggers ZAP’s active scanner on all discovered URLs  

This gives you **full-stack coverage**:

- ZAP passive scan  
- ZAP active scan  
- Playwright browser‑side OWASP tests  

---

# 🧪 **OWASP Browser‑Side Tests Included**

Below is a complete list of all tests the suite performs, grouped by OWASP category.

---

## 🔐 **A01 — Broken Access Control**
- Accessing sensitive routes without authentication (`/admin`, `/settings`, `/internal`)
- Open redirect detection (`redirect=`, `next=`, `returnUrl=`)
- Weak password reset flow (missing email verification)

---

## 🔑 **A02 — Cryptographic Failures**
- Cookies missing `Secure`, `HttpOnly`, or `SameSite`
- Mixed content (HTTP resources on HTTPS pages)
- Missing HSTS header
- Sensitive data stored in `localStorage` or `sessionStorage`
- Hardcoded secrets in JavaScript
- JWT decoding performed client‑side
- Insecure WebSocket usage (`ws://` instead of `wss://`)

---

## 🧨 **A03 — Injection**
- DOM‑based XSS detection (script injection, event handlers)
- Reflected parameter injection (`?q=payload`)
- Dangerous JS functions (`eval`, `new Function`)
- Prototype pollution indicators
- DOM clobbering (`window.id` overwritten)

---

## 🏗️ **A04 — Insecure Design**
- Weak password policy (accepting trivial passwords)
- Missing validation on sensitive fields

---

## 📦 **A05 — Security Misconfiguration**
- Missing or weak CSP (`unsafe-inline`, `unsafe-eval`)
- CSP nonce reuse
- Missing X‑Frame‑Options / frame‑ancestors (clickjacking)
- Missing Permissions‑Policy header
- Missing Cache‑Control header
- Weak iframe sandboxing
- CORS misconfiguration (`Access-Control-Allow-Origin: *`)
- Exposed environment variables (`process.env`)
- Insecure third‑party widget loading

---

## 🧬 **A06 — Vulnerable & Outdated Components**
- React DevTools hook present in production
- React version leaked to the client

---

## 🔐 **A07 — Identification & Authentication Failures**
- Login page missing password field
- OAuth implicit flow detected (`access_token` in URL fragment)

---

## 🧱 **A08 — Software & Data Integrity Failures**
- Insecure script loading (`http://cdn…`)
- Service Worker active (potential caching of sensitive data)

---

## 📉 **A09 — Security Logging & Monitoring Failures**
- JavaScript console errors detected during browsing

---

## 🌐 **A10 — Server-Side Request Forgery Indicators**
- Client-side fetch calls to internal metadata endpoints  
  (`169.254.*`, `metadata.google.internal`, `localhost`)

---

# 🧭 **SPA / React / Modern Frontend Tests**
These tests are specifically designed for modern JavaScript applications:

- SPA route enumeration (React Router route leaks)
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

---

# 📊 **How Results Are Reported**

Each finding is converted into a ZAP alert with:

- **URL**  
- **Description**  
- **Evidence**  
- **OWASP category**  
- **Medium risk / High confidence** (default)

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

It adds **browser‑side intelligence** that ZAP’s core engine cannot provide.

---

# 🧩 **Ideal Use Cases**

- Testing **React / Angular / Vue** apps  
- Testing **SPAs** with dynamic routing  
- Detecting **DOM‑based vulnerabilities**  
- Detecting **client‑side misconfigurations**  
- Strengthening **CI/CD pipelines**  
- Enhancing **ZAP Automation Framework** scans  

---

# 🏁 **Summary**

The PlaywrightClient add-on transforms ZAP into a **full browser‑aware security scanner**, capable of detecting modern client‑side vulnerabilities that traditional scanners miss.

It provides:

- A real browser  
- A full OWASP test suite  
- SPA‑aware crawling  
- Automatic ZAP alert creation  
- Seamless integration with ZAP’s scanning engine  

---