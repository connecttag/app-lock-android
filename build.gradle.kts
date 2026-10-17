plugins {
    alias(libs.plugins.android.library)
    `maven-publish`
}

group = "org.connecttag.libs.kotlin"
version = "1.0.0"

android {
    namespace = "org.connecttag.features.applock"
    compileSdk = 36

    defaultConfig {
        minSdk = 26
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    publishing {
        singleVariant("release") {
            withSourcesJar()
        }
    }
}

dependencies {
    implementation(libs.androidx.ktx)
    implementation(libs.androidx.biometric)
    implementation(libs.androidx.lifecycle.process)
}

publishing {
    publications {
        create<MavenPublication>("release") {
            from(components["release"])
            groupId = "org.connecttag.libs.kotlin"
            artifactId = "app-lock-android"
            version = "1.0.0"

            pom {
                name.set("ConnectTag App Lock Android")
                description.set("Android app-lock primitives for lock state, attempt tracking, biometric capability checks, and local state storage")
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
