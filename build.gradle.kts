plugins {
    kotlin("jvm") version "1.9.22"
    application
}

group = "pro.authon"
version = "1.0.0"

repositories {
    mavenCentral()
}

dependencies {
    // No external dependencies - uses java.net.http from JDK 11+
}

application {
    mainClass.set("pro.authon.sdk.ExampleKt")
}

kotlin {
    jvmToolchain(11)
}

tasks.jar {
    manifest {
        attributes["Main-Class"] = "pro.authon.sdk.ExampleKt"
    }
    from(configurations.runtimeClasspath.get().map { if (it.isDirectory) it else zipTree(it) })
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
}
