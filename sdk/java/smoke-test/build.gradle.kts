plugins {
    kotlin("jvm") version "1.9.25"
    application
}

repositories {
    mavenLocal()
    mavenCentral()
}

dependencies {
    implementation("com.hyperswitch:payments-client:0.1.0")
    implementation("org.json:json:20240303")
}

application {
    mainClass.set("SmokeTestKt")
}

tasks.named<JavaExec>("run") {
    systemProperty("jna.library.path",
        file("../src/main/resources/native").absolutePath)
}
