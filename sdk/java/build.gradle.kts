plugins {
    kotlin("jvm") version "1.9.25"
    `java-library`
    `maven-publish`
}

group = "com.hyperswitch"
version = "0.1.0"

repositories {
    mavenCentral()
}

dependencies {
    // api = exposed to consumers at compile time (published as compile scope in POM)
    // Version must match protoc (protoc --version → libprotoc X.Y → protobuf-java 4.X.Y)
    api("com.google.protobuf:protobuf-java:4.33.4")
    // JNA required by UniFFI-generated Kotlin bindings (exposed in public API)
    api("net.java.dev.jna:jna:5.14.0")
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
    implementation("org.json:json:20240303")
}

publishing {
    publications {
        create<MavenPublication>("maven") {
            groupId = "com.hyperswitch"
            artifactId = "payments-client"
            from(components["java"])
        }
    }
}
