import com.vanniktech.maven.publish.AndroidSingleVariantLibrary
import com.vanniktech.maven.publish.SonatypeHost

plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.vanniktech.mavenPublish)
    signing
}

android {
    namespace = "io.github.areyougarou.intakto"
    compileSdk = 35
    ndkVersion = "27.2.12479018"

    defaultConfig {
        minSdk = 26
        consumerProguardFiles("consumer-rules.pro")
        externalNativeBuild { cmake { abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86_64", "x86") } }
    }

    externalNativeBuild {
        cmake {
            path = file("../native/CMakeLists.txt")
            version = "3.22.1"
        }
    }

    // Java 11 bytecode (not 17) so adopter projects on Java 11 compatibility -- including Android
    // Studio's default new-project template -- can consume the library. The SDK is pure Kotlin and
    // uses no Java 17 APIs, so this only lowers the class-file version, from 61 to 55.
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
    kotlinOptions { jvmTarget = "11" }
}

mavenPublishing {
    configure(AndroidSingleVariantLibrary("release", sourcesJar = true, publishJavadocJar = true))
    coordinates("io.github.areyougarou", "intakto", "0.2.1")
    publishToMavenCentral(SonatypeHost.CENTRAL_PORTAL)
    if (providers.gradleProperty("signing.gnupg.keyName").isPresent) {
        signAllPublications()
    }
    pom {
        name.set("IntaktoFT")
        description.set("Lightweight Android RASP (runtime app self-protection) library - free tier.")
        url.set("https://github.com/areyougarou/IntaktoFT")
        licenses {
            license {
                name.set("The Apache License, Version 2.0")
                url.set("https://www.apache.org/licenses/LICENSE-2.0.txt")
            }
        }
        developers {
            developer {
                id.set("areyougarou")
                name.set("areyougarou")
            }
        }
        scm {
            url.set("https://github.com/areyougarou/IntaktoFT")
            connection.set("scm:git:https://github.com/areyougarou/IntaktoFT.git")
            developerConnection.set("scm:git:ssh://git@github.com/areyougarou/IntaktoFT.git")
        }
    }
}

signing {
    useGpgCmd()
}
