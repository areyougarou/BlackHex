import com.vanniktech.maven.publish.AndroidSingleVariantLibrary
import com.vanniktech.maven.publish.SonatypeHost

plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.vanniktech.mavenPublish)
    signing
}

android {
    namespace = "rasp.sdk"
    compileSdk = 35
    ndkVersion = "27.2.12479018"

    defaultConfig {
        minSdk = 26
        consumerProguardFiles("consumer-rules.pro")
        externalNativeBuild { cmake { abiFilters += "arm64-v8a" } }
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
    coordinates("io.github.areyougarou", "blackhex", "0.1.0")
    publishToMavenCentral(SonatypeHost.CENTRAL_PORTAL)
    if (providers.gradleProperty("signing.gnupg.keyName").isPresent) {
        signAllPublications()
    }
    pom {
        name.set("BlackHex")
        description.set("Lightweight Android RASP (runtime app self-protection) library - free tier.")
        url.set("https://github.com/areyougarou/BlackHex")
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
            url.set("https://github.com/areyougarou/BlackHex")
            connection.set("scm:git:https://github.com/areyougarou/BlackHex.git")
            developerConnection.set("scm:git:ssh://git@github.com/areyougarou/BlackHex.git")
        }
    }
}

signing {
    useGpgCmd()
}
