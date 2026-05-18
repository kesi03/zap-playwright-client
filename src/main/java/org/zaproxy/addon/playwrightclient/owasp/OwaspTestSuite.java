package org.zaproxy.addon.playwrightclient.owasp;

import com.microsoft.playwright.*;

import java.util.*;

public class OwaspTestSuite {

    public static List<OwaspTestFinding> runAll(Page page, BrowserContext context, String baseUrl) {
        List<OwaspTestFinding> all = new ArrayList<>();

        all.addAll(OwaspA01_BrokenAccessControl.test(page, baseUrl));
        all.addAll(OwaspA02_CryptographicFailures.test(context));
        all.addAll(OwaspA03_Injection_DOMXSS.test(page));
        all.addAll(Owasp_DOMXSS_Advanced.test(page));
        all.addAll(Owasp_ReflectedParams.test(page, baseUrl));
        all.addAll(OwaspA04_InsecureDesign.test(page, baseUrl));
        all.addAll(OwaspA05_SecurityMisconfiguration.test(page));
        all.addAll(Owasp_CSP_Bypass.test(page));
        all.addAll(Owasp_CORS_Misconfig.test(page));
        all.addAll(Owasp_WeakCORS_Preflight.test(page));
        all.addAll(Owasp_MixedContent.test(page));
        all.addAll(OwaspA06_OutdatedComponents.test(page));
        all.addAll(Owasp_ReactHydrationErrors.test(page));
        all.addAll(Owasp_ServiceWorker.test(page));
        all.addAll(Owasp_StorageSecrets.test(page));
        all.addAll(Owasp_JWT_Weakness.test(page));
        all.addAll(Owasp_AutocompleteSensitive.test(page));
        all.addAll(Owasp_Clickjacking.test(page));
        all.addAll(Owasp_CacheControl.test(page));
        all.addAll(Owasp_HardcodedCredentials.test(page));
        all.addAll(OwaspA07_AuthFailures.test(page, baseUrl));
        all.addAll(OwaspA08_IntegrityFailures.test(page));
        all.addAll(OwaspA09_LoggingMonitoring.test(page));
        all.addAll(OwaspA10_SSRFIndicators.test(page));
        all.addAll(Owasp_WeakPasswordReset.test(page, baseUrl));
        all.addAll(Owasp_OAuth_Misconfig.test(page));
        all.addAll(Owasp_SPA_RouteEnumeration.test(page));
        all.addAll(Owasp_PrototypePollution.test(page));
        all.addAll(Owasp_DOM_Clobbering.test(page));
        all.addAll(Owasp_ClientPathTraversal.test(page, baseUrl));
        all.addAll(Owasp_OpenRedirect.test(page, baseUrl));
        all.addAll(Owasp_SensitiveData_JS.test(page));

        // Batch 3 & 4 additional checks
        all.addAll(Owasp_GraphQL_Introspection.test(page, baseUrl));
        all.addAll(Owasp_OAuth_ImplicitFlow.test(page));
        all.addAll(Owasp_FileUpload_Insecure.test(page));
        all.addAll(Owasp_HSTS.test(page));
        all.addAll(Owasp_WebSocket_Insecure.test(page));
        all.addAll(Owasp_DangerousJSFunctions.test(page));
        all.addAll(Owasp_EnvLeak.test(page));
        all.addAll(Owasp_FeaturePolicy.test(page));
        all.addAll(Owasp_CSP_NonceReuse.test(page));
        all.addAll(Owasp_ThirdPartyWidgets.test(page));

        return all;
    }
}
