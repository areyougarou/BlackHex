import com.vanniktech.maven.publish.AndroidSingleVariantLibrary
import com.vanniktech.maven.publish.SonatypeHost
import javax.inject.Inject

plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.vanniktech.mavenPublish)
    signing
}

android {
    namespace = "io.github.areyougarou.blackhex"
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

    packaging {
        jniLibs {
            excludes += listOf("**/armeabi-v7a/libblackhex.so", "**/x86/libblackhex.so", "**/x86_64/libblackhex.so")
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

abstract class StageAbiAssets : DefaultTask() {
    @get:InputFiles
    abstract val nativeLibs: ConfigurableFileCollection

    @get:Internal
    abstract val ndkDir: DirectoryProperty

    @get:OutputDirectory
    abstract val outputDir: DirectoryProperty

    @get:Inject
    abstract val execOps: ExecOperations

    @TaskAction
    fun stage() {
        val bin = ndkDir.get().asFile.resolve("toolchains/llvm/prebuilt").listFiles()!!.single().resolve("bin")
        val strip = bin.listFiles()!!.single { it.nameWithoutExtension == "llvm-strip" }
        val out = outputDir.get().asFile.apply { deleteRecursively() }
        listOf("armeabi-v7a", "x86", "x86_64").forEach { abi ->
            val src = nativeLibs.asFileTree.matching { include("**/$abi/libblackhex.so") }.singleFile
            val dst = out.resolve("blackhex/$abi/libblackhex.so").apply { parentFile.mkdirs() }
            execOps.exec { commandLine(strip, "-o", dst, src) }
        }
    }
}

androidComponents {
    onVariants { variant ->
        val name = variant.name.replaceFirstChar { it.uppercase() }
        val stage = tasks.register<StageAbiAssets>("stage${name}AbiAssets") {
            nativeLibs.from(tasks.named("externalNativeBuild$name"))
            ndkDir.set(android.ndkDirectory)
        }
        variant.sources.assets?.addGeneratedSourceDirectory(stage, StageAbiAssets::outputDir)
    }
}
