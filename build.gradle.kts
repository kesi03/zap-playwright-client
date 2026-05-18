import org.zaproxy.gradle.addon.AddOnStatus

plugins {
    java
    kotlin("jvm") version "1.9.23" apply false
    id("com.github.johnrengelman.shadow") version "8.1.1"
    id("org.zaproxy.add-on") version "0.13.1"
}

group = "org.zaproxy.addon"
version = "0.1.0"

repositories {
    mavenCentral()
    mavenLocal()
    maven("https://repo.zaproxy.org/maven2/")
}

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(17))
    }
}

dependencies {
    // ZAP add-on API
    compileOnly("org.zaproxy:zap:2.15.0")

    // Playwright for Java
    implementation("com.microsoft.playwright:playwright:1.44.0")
    implementation("org.json:json:20230227")

    // Logging
    implementation("org.slf4j:slf4j-api:2.0.12")
    implementation("org.slf4j:slf4j-simple:2.0.12")

    // Testing
    testImplementation("org.junit.jupiter:junit-jupiter:5.10.2")
}

tasks.test {
    useJUnitPlatform()
}

tasks.shadowJar {
    archiveClassifier.set("")
    mergeServiceFiles()
    minimize()
}

//
// --- GENERATED RESOURCES (ZapAddOn.xml) ---
//

val generateZapAddOnXml by tasks.registering {
    val outputDir = layout.buildDirectory.dir("generated-resources")

    outputs.dir(outputDir)

    doLast {
        val file = outputDir.get().file("ZapAddOn.xml").asFile
        file.parentFile.mkdirs()
        file.writeText(
            """
            <addon id="playwrightclient"
                   version="$version"
                   status="alpha"
                   author="Kester"
                   name="Playwright Client"
                   description="Playwright-powered crawler and OWASP browser tests">
                <dependencies>
                    <zapaddon id="core" />
                </dependencies>
            </addon>
            """.trimIndent()
        )
    }
}

//
// --- RESOURCE PIPELINE FIX ---
//

sourceSets["main"].resources.srcDir("src/main/resources")
sourceSets["main"].resources.srcDir(generateZapAddOnXml.map { it.outputs.files })

tasks.named("processResources") {
    dependsOn(generateZapAddOnXml)
}

//
// --- JAR MANIFEST ---
//

tasks.jar {
    manifest {
        attributes(
            "Manifest-Version" to "1.0",
            "Add-On-Name" to "PlaywrightClient",
            "Add-On-Version" to version,
            "Add-On-Author" to "Kester",
            "Add-On-Description" to "Playwright-powered crawler and OWASP browser tests"
        )
    }
}

//
// --- ZAP ADD-ON CONFIG ---
//

zapAddOn {
    addOnId.set("playwrightclient")
    addOnName.set("Playwright Client")
    zapVersion.set("2.15.0")
    addOnStatus.set(AddOnStatus.ALPHA)

    manifest {
        author.set("Kester")
        url.set("https://github.com/your-org/zap-playwright-client")
        extensions {
            register("org.zaproxy.addon.playwrightclient.ExtensionPlaywrightClient")
        }
    }
}
