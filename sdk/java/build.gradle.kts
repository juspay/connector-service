plugins {
    kotlin("jvm") version "2.3.10"
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

    // Cucumber BDD test dependencies
    testImplementation("io.cucumber:cucumber-java:7.22.0")
    testImplementation("io.cucumber:cucumber-junit:7.22.0")
    testImplementation("junit:junit:4.13.2")
}

// Create a separate source set for the sanity runner
sourceSets {
    create("sanity") {
        kotlin.srcDir("tests")
        compileClasspath += sourceSets["main"].output + sourceSets["main"].compileClasspath
        runtimeClasspath += sourceSets["main"].output + sourceSets["main"].runtimeClasspath
    }
    // Cucumber BDD test source set
    create("cucumberTest") {
        kotlin.srcDir("tests/cucumber")
        compileClasspath += sourceSets["main"].output + sourceSets["main"].compileClasspath + configurations["testCompileClasspath"]
        runtimeClasspath += sourceSets["main"].output + sourceSets["main"].runtimeClasspath + configurations["testRuntimeClasspath"]
    }
}

// Compile the sanity runner
tasks.named<org.jetbrains.kotlin.gradle.tasks.KotlinCompile>("compileSanityKotlin") {
    dependsOn("compileKotlin")
}

tasks.register<JavaExec>("runClientSanity") {
    group = "verification"
    description = "Run client sanity certification runner"
    mainClass.set("ClientSanityRunnerKt")
    classpath = sourceSets["sanity"].runtimeClasspath
    standardInput = System.`in`
    systemProperty("jna.library.path",
        file("src/main/resources/native").absolutePath)
    dependsOn("compileSanityKotlin")
}

// Compile cucumber test sources
tasks.named<org.jetbrains.kotlin.gradle.tasks.KotlinCompile>("compileCucumberTestKotlin") {
    dependsOn("compileKotlin")
}

tasks.register<JavaExec>("runCucumber") {
    group = "verification"
    description = "Run Cucumber BDD tests for client sanity"
    mainClass.set("io.cucumber.core.cli.Main")
    classpath = sourceSets["cucumberTest"].runtimeClasspath
    systemProperty("jna.library.path",
        file("src/main/resources/native").absolutePath)
    systemProperty("artifacts.dir",
        file("../tests/client_sanity/artifacts").absolutePath)
    args = listOf(
        "--glue", "cucumber",
        "--tags", "not @skip_kotlin",
        "--plugin", "pretty",
        "--plugin", "json:../tests/client_sanity/artifacts/cucumber_kotlin.json",
        "../tests/client_sanity/features"
    )
    dependsOn("compileCucumberTestKotlin")
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
