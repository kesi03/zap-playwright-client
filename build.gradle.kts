import org.zaproxy.gradle.addon.AddOnStatus

plugins {
    java
    kotlin("jvm") version "1.9.23" apply false
    id("com.github.johnrengelman.shadow") version "8.1.1"
    id("org.zaproxy.add-on") version "0.13.1"
}

group = "org.zaproxy.addon"
version = "0.1.1"

repositories {
    mavenCentral()
    mavenLocal()
    maven("https://repo.zaproxy.org/maven2/")
}

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(21))
    }
}

dependencies {
    // ZAP add-on API
    compileOnly("org.zaproxy:zap:2.15.0")

    // Playwright for Java
    implementation("com.microsoft.playwright:playwright:1.59.0")
    implementation("org.json:json:20230227")

    // Logging
    implementation("org.slf4j:slf4j-api:2.0.12")
    implementation("org.slf4j:slf4j-simple:2.0.12")

    // Testing
    testImplementation("org.junit.jupiter:junit-jupiter:5.10.2")

    // Local automation add-on for compilation (automation framework API)
    compileOnly(files("libs/automation-beta-0.60.0.jar"))
}

tasks.test {
    useJUnitPlatform()
}

tasks.shadowJar {
    archiveClassifier.set("")
    mergeServiceFiles()
    // Do not minimize: keep all Playwright driver resources needed at runtime
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
        dependencies {
            addOns {
                register("automation") {
                    version.set(">=0.4.0")
                }
            }
        }
        extensions {
            register("org.zaproxy.addon.playwrightclient.ExtensionPlaywrightClient")
        }
    }
}
