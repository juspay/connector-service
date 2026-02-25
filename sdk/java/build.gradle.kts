plugins {
    kotlin("jvm") version "1.9.25"
    application
}

repositories {
    mavenCentral()
}

dependencies {
    // Version must match protoc (protoc --version → libprotoc X.Y → protobuf-java 4.X.Y)
    implementation("com.google.protobuf:protobuf-java:4.33.4")
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
    implementation("org.json:json:20240303")
    // JNA required by UniFFI-generated Kotlin bindings
    implementation("net.java.dev.jna:jna:5.14.0")
}

application {
    mainClass.set("ExampleKt")
}

// Add generated UniFFI + protobuf sources
sourceSets {
    main {
        kotlin.srcDir("generated")
        java.srcDir("generated")
    }
}

// Pass the library path so JNA can find the native library
tasks.named<JavaExec>("run") {
    systemProperty("jna.library.path", file("generated").absolutePath)
}
