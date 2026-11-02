package com.zeronet.mobile.ui.myserver

import android.content.Context
import java.io.File

/**
 * The Zray server program the app ships (one file per CPU under
 * `assets/zray/`). The installer uploads it over SSH, so installing a server
 * needs no GitHub release. Returns the folder holding the unpacked files, or
 * `null` when this build carries none (the installer then falls back to the
 * signed release).
 */
object ServerProgram {
    private val files = listOf("zray-linux-x64", "zray-linux-arm64")

    fun dir(context: Context): String? {
        val out = File(context.filesDir, "zray-server").apply { mkdirs() }
        var any = false
        for (name in files) {
            val target = File(out, name)
            val size = try {
                context.assets.openFd("zray/$name").use { it.length }
            } catch (_: Exception) {
                // Compressed assets have no fd; fall back to a stream below.
                -1L
            }
            try {
                if (!target.exists() || (size >= 0 && target.length() != size)) {
                    context.assets.open("zray/$name").use { input ->
                        target.outputStream().use { input.copyTo(it) }
                    }
                }
                any = true
            } catch (_: Exception) {
                // This CPU's program is not in the build.
                target.delete()
            }
        }
        return if (File(out, "zray-linux-x64").exists() && any) out.absolutePath else null
    }
}
