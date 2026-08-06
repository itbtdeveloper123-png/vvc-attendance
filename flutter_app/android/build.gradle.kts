allprojects {
    repositories {
        google()
        mavenCentral()
    }
}

// Keep Flutter's standard output path: flutter_app/build/
val newBuildDir: Directory =
    rootProject.layout.buildDirectory
        .dir("../../build")
        .get()
rootProject.layout.buildDirectory.value(newBuildDir)

subprojects {
    if (project.name == "app") {
        // :app must output to Flutter's expected location (flutter_app/build/app)
        project.layout.buildDirectory.value(newBuildDir.dir(project.name))
    } else {
        // Plugin subprojects must stay on the SAME drive as the project (F:).
        // newBuildDir resolves to flutter_app/build which may differ from the
        // pub-cache drive (C:), triggering a "different roots" Gradle error.
        val pluginBuildDir =
            rootProject.layout.projectDirectory.dir("build/${project.name}")
        project.layout.buildDirectory.value(pluginBuildDir)
    }
}
subprojects {
    project.evaluationDependsOn(":app")
}

subprojects {
    plugins.withId("com.android.library") {
        val android = extensions.findByName("android")
        if (android != null) {
            try {
                val getNamespace = android.javaClass.getMethod("getNamespace")
                if (getNamespace.invoke(android) == null) {
                    val setNamespace = android.javaClass.getMethod("setNamespace", String::class.java)
                    setNamespace.invoke(android, "com.example.${project.name.replace("-", "_")}")
                }
            } catch (_: Exception) {
            }
        }
        val manifestFile = file("src/main/AndroidManifest.xml")
        if (manifestFile.exists()) {
            val content = manifestFile.readText()
            if (content.contains("package=")) {
                val updatedContent = content.replace(Regex("""package="[^"]*""""), "")
                manifestFile.writeText(updatedContent)
            }
        }
    }
}

tasks.register<Delete>("clean") {
    delete(rootProject.layout.buildDirectory)
}

