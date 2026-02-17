plugins {
    java
    kotlin("jvm") version "1.9.22"
    application
}

group = "io.juspay.connector"
version = "0.1.0"

repositories {
    mavenCentral()
}

dependencies {
    // JNA for native library loading (required by UniFFI Kotlin bindings)
    implementation("net.java.dev.jna:jna:5.14.0")

    // Kotlin stdlib (needed for the auto-generated Kotlin bindings)
    implementation(kotlin("stdlib"))
}

java {
    sourceCompatibility = JavaVersion.VERSION_11
    targetCompatibility = JavaVersion.VERSION_11
}

kotlin {
    jvmToolchain(11)
}

// The auto-generated Kotlin bindings live alongside the Java sources
sourceSets {
    main {
        // Include the auto-generated UniFFI Kotlin bindings
        kotlin.srcDir("src/main/kotlin")
        java.srcDir("src/main/java")
    }
}

application {
    mainClass.set("io.juspay.connector.example.ConnectorExample")
}

tasks.named<JavaExec>("run") {
    // Point JNA to the directory containing libconnector_ffi_uniffi.so / .dylib / .dll
    val libDir = project.findProperty("nativeLibDir")
        ?: "${rootProject.projectDir}/../../../../target/release"
    jvmArgs("-Djna.library.path=$libDir")
}
