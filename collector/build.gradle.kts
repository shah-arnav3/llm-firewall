// llm-firewall collector: receives Captures from llmfw-proxy over a Unix socket.
// Parsing, labelling, detection and storage are added as they are built.

plugins {
    java
    application
    id("com.google.protobuf") version "0.10.0"
}

group = "dev.llmfirewall"
version = "0.1.0"

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(21))
    }
}

// protobuf-java must match the protoc that generates the Java sources.
val protobufVersion = "4.36.2"

dependencies {
    // Wire contract, generated from ../proto/capture.proto. Plain protobuf, no gRPC.
    implementation("com.google.protobuf:protobuf-java:$protobufVersion")
    // llm-firewall.yaml, read with SafeConstructor only.
    implementation("org.yaml:snakeyaml:2.7")

    testImplementation(platform("org.junit:junit-bom:6.1.3"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

sourceSets {
    main {
        proto {
            srcDir("../proto")
        }
    }
}

protobuf {
    protoc {
        artifact = "com.google.protobuf:protoc:$protobufVersion"
    }
}

application {
    mainClass.set("dev.llmfirewall.collector.CollectorMain")
    applicationName = "llmfw-collector"
}

tasks.withType<JavaCompile>().configureEach {
    options.release.set(21)
    options.compilerArgs.addAll(listOf("-Xlint:all", "-Werror"))
}

tasks.test {
    useJUnitPlatform()
}
