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

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
}

mavenPublishing {
    configure(AndroidSingleVariantLibrary("release", sourcesJar = true, publishJavadocJar = true))
    coordinates("io.github.areyougarou", "intakto", "0.2.0")
    publishToMavenCentral(SonatypeHost.CENTRAL_PORTAL)
    if (providers.gradleProperty("signing.gnupg.keyName").isPresent) {
        signAllPublications()
    }
    pom {
        name.set("Intakto")
        description.set("Lightweight Android RASP (runtime app self-protection) library - free tier.")
        url.set("https://github.com/areyougarou/Intakto")
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
            url.set("https://github.com/areyougarou/Intakto")
            connection.set("scm:git:https://github.com/areyougarou/Intakto.git")
            developerConnection.set("scm:git:ssh://git@github.com/areyougarou/Intakto.git")
        }
    }
}

signing {
    useGpgCmd()
}
