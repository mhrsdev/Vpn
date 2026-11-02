package com.zeronet.mobile.core

import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import org.json.JSONObject

/**
 * Call sites for the JNI additions owned by the **routing agent**
 * (`ZrayNative.kt` — hands off for this agent).
 *
 * Frozen signatures (Design B §4.3, Design D §5.1):
 * - `routingHealth(): String`
 * - `setRoutingMode(requestJson: String): String?` (null = success)
 * - `probeNow(): String?` (null = success)
 * - `pairTest(tag: String): String`
 * - `adminCall(requestJson: String, listener: NativeListener): Long`
 *
 * None of these exist in this worktree's `ZrayNative.kt` yet. Until the
 * routing agent lands them, every call fails fast with a clear message —
 * the UI surfaces it honestly instead of showing fake data. Do NOT invent
 * the native side here.
 */
object NativeExtras {

    private const val PENDING = "not wired yet (owned by the routing agent)"

    /**
     * Whether the extended JNI surface is present in the loaded native
     * library. Checked by reflection so the app degrades honestly on builds
     * whose native side predates the routing agent's work.
     */
    val routingNativeAvailable: Boolean by lazy {
        runCatching {
            val k = ZrayNative::class.java
            k.getMethod("routingHealth") != null &&
                k.getMethod("setRoutingMode", String::class.java) != null &&
                k.getMethod("probeNow") != null &&
                k.getMethod("pairTest", String::class.java) != null &&
                k.getMethod("adminCall", String::class.java, NativeListener::class.java) != null
        }.getOrDefault(false)
    }

    fun routingHealth(): JSONObject {
        if (!routingNativeAvailable) throw UnsupportedOperationException("ZrayNative.routingHealth $PENDING")
        return JSONObject(ZrayNative.routingHealth())
    }

    /** Null on success, error string otherwise (existing convention). */
    fun setRoutingMode(request: JSONObject): String? {
        if (!routingNativeAvailable) return "setRoutingMode $PENDING"
        return ZrayNative.setRoutingMode(request.toString())
    }

    fun probeNow(): String? {
        if (!routingNativeAvailable) return "probeNow $PENDING"
        return ZrayNative.probeNow()
    }

    fun pairTest(tag: String): JSONObject {
        if (!routingNativeAvailable) throw UnsupportedOperationException("ZrayNative.pairTest $PENDING")
        return JSONObject(ZrayNative.pairTest(tag))
    }

    /**
     * Management-plane calls to the pair's admin API (Design C `/api/v1`).
     *
     * Request envelope: `{"op":"admin","method":"GET","path":"/api/v1/users",
     * "query":{...},"body":{...},"pair_id":"…","token":"<bearer, per call>",
     * "pair_record":{…},"target":"exit"|"gateway"}`. The bearer <redacted> passed
     * per call from Kotlin memory, never persisted in Rust. Events stream
     * like `serverJob`: `{"t":"step"|"detail"|"done"}`.
     */
    fun adminCallFlow(request: JSONObject): Flow<JSONObject> = flow {
        if (!routingNativeAvailable) {
            emit(JSONObject().put("t", "done").put("ok", false)
                .put("error", "Admin bridge unavailable: ZrayNative.adminCall $PENDING"))
            return@flow
        }
        // The request may hold the admin bearer <redacted> is never logged.
        com.zeronet.mobile.service.nativeJob { listener ->
            ZrayNative.adminCall(request.toString(), listener)
        }.collect { emit(it) }
    }
}
