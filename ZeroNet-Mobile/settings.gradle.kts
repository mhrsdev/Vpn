pluginManagement {
    repositories {
        google {
            content {
                includeGroupByRegex("com\\.android.*")
                includeGroupByRegex("com\\.google.*")
                includeGroupByRegex("androidx.*")
            }
        }
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        // The original developer's local mirror, made opt-in and portable:
        // enabled via the ZERONET_M2MIRROR env var or the `m2mirror` Gradle
        // property, and only when the path actually exists. Everywhere else
        // the build resolves from Google and Maven Central.
        val mirrorDir = providers.environmentVariable("ZERONET_M2MIRROR")
            .orElse(providers.gradleProperty("m2mirror")).orNull
            ?.let { file(it) }?.takeIf { it.exists() }
        if (mirrorDir != null) {
            maven {
                url = mirrorDir.toURI()
                metadataSources {
                    gradleMetadata()
                    mavenPom()
                    artifact()
                }
            }
        }
        google()
        mavenCentral()
    }
}

rootProject.name = "ZeroNet"
include(":app")
