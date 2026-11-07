plugins {
    alias(libs.plugins.android.library)
    `maven-publish`
}

// JitPack supplies transport coordinates; normal Maven publishing keeps the
// canonical ConnectTag identity declared in gradle.properties.
val publicationArtifact = providers.environmentVariable("ARTIFACT")
    .orElse(providers.gradleProperty("LIB_ARTIFACT_ID")).get()
group = providers.gradleProperty("group")
    .orElse(providers.environmentVariable("GROUP"))
    .orElse(providers.gradleProperty("LIB_GROUP")).get()
version = providers.gradleProperty("version")
    .orElse(providers.environmentVariable("VERSION"))
    .orElse(providers.gradleProperty("LIB_VERSION")).get()

kotlin {
    jvmToolchain(21)
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_21)
    }
}

android {
    namespace = "org.connecttag.lib.features.applock"
    compileSdk = 37

    defaultConfig {
        minSdk = 26
    }

    packaging {
        jniLibs {
            useLegacyPackaging = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_21
        targetCompatibility = JavaVersion.VERSION_21
    }

    publishing {
        singleVariant("release") {
            withSourcesJar()
        }
    }
}

dependencies {
    implementation(libs.androidx.ktx)
    implementation(libs.androidx.appcompat)
    api(libs.androidx.biometric)
    implementation(libs.androidx.lifecycle.process)
    api(libs.kotlinx.coroutines.core)

    testImplementation(libs.junit4)
}

afterEvaluate {
    publishing {
        publications {
            create<MavenPublication>("release") {
                from(components["release"])
                groupId = project.group.toString()
                artifactId = publicationArtifact
                version = project.version.toString()

                pom {
                    name.set("ConnectTag App Lock Android")
                    description.set("Enterprise Android App Lock & PIN security library with PBKDF2-HMAC-SHA256, Master/Duress PINs, Android Keystore HMAC tamper detection, BiometricPrompt authenticator, and launcher camouflage")
                    url.set("https://github.com/connecttag/app-lock-android")
                    licenses {
                        license {
                            name.set("The Apache License, Version 2.0")
                            url.set("https://www.apache.org/licenses/LICENSE-2.0.txt")
                        }
                    }
                    developers {
                        developer {
                            id.set("connecttagye")
                            name.set("Connect Tag")
                            email.set("connecttagye@gmail.com")
                        }
                    }
                    scm {
                        connection.set("scm:git:https://github.com/connecttag/app-lock-android.git")
                        developerConnection.set("scm:git:ssh://git@github.com:connecttag/app-lock-android.git")
                        url.set("https://github.com/connecttag/app-lock-android/tree/main")
                    }
                }
            }
        }
    }
}
