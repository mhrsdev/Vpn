package com.zeronet.mobile.ui.admin

import org.json.JSONArray
import org.json.JSONObject

/**
 * The management plane's data shapes and request builders, against the
 * frozen `/api/v1` contract (Design C).
 *
 * Transport: the requests built here ride `NativeExtras.adminCallFlow`
 * (routing agent's `ZrayNative.adminCall`, op `"admin"`), which forwards
 * them over SSH to the exit server's loopback-only admin API. The bearer
 * <redacted> is supplied per call from the pair record — never logged, never
 * persisted anywhere new.
 *
 * Pure functions only: parsing and request building are unit-tested without
 * any backend.
 */
object AdminApi {

    data class AdminUser(
        val id: String,
        val name: String,
        val note: String?,
        val quotaBytes: Long?,
        val quotaMbps: Int?,
        val maxDevices: Int?,
        val expiresAt: Long?,
        val enabled: Boolean,
    )

    data class AdminDevice(
        val id: String,
        val userId: String,
        val label: String,
        val identityHash: String,
        val up: Long,
        val down: Long,
        val enabled: Boolean,
    )

    /** Issued once, at device creation: the only response that carries secrets. */
    data class DeviceCredentials(
        val inboundTag: String,
        val protocol: String,
        val link: String,
        val qrSvg: String,
    )

    data class Subscription(
        val id: String,
        val deviceId: String?,
        val name: String?,
        val url: String,
        val qrText: String,
        val expiresAt: Long?,
        val managed: Boolean,
    )

    data class DnsPolicy(val mode: String, val resolvers: List<String>, val note: String?)

    data class ServerInfo(
        val role: String,
        val host: String,
        val engineReachable: Boolean,
        val tunnelState: String?,
        val tunnelRttMs: Long?,
    )

    data class Traffic(val up: Long, val down: Long)

    /**
     * One management call. `token` and `pair_id` are filled in by
     * [AdminModel] from the open pair's record — callers only name the
     * method, path and body.
     */
    fun request(method: String, path: String, query: JSONObject? = null, body: JSONObject? = null): JSONObject =
        JSONObject()
            .put("op", "admin")
            .put("method", method)
            .put("path", path)
            .put("query", query ?: JSONObject())
            .put("body", body ?: JSONObject())

    fun parseUsers(array: JSONArray): List<AdminUser> =
        array.objects().map {
            AdminUser(
                id = it.getString("id"),
                name = it.optString("name"),
                note = it.optString("note").takeIf { s -> s.isNotEmpty() },
                quotaBytes = it.optLong("quota_bytes").takeIf { _ -> it.has("quota_bytes") && !it.isNull("quota_bytes") },
                quotaMbps = it.optInt("quota_mbps").takeIf { _ -> it.has("quota_mbps") && !it.isNull("quota_mbps") },
                maxDevices = it.optInt("max_devices").takeIf { _ -> it.has("max_devices") && !it.isNull("max_devices") },
                expiresAt = it.optLong("expires_at").takeIf { _ -> it.has("expires_at") && !it.isNull("expires_at") },
                // The panel reports `revoked`; an `enabled` flag wins if present.
                enabled = if (it.has("enabled")) it.optBoolean("enabled", true) else !it.optBoolean("revoked", false),
            )
        }

    fun parseDevices(array: JSONArray): List<AdminDevice> =
        array.objects().map {
            AdminDevice(
                id = it.getString("id"),
                userId = it.optString("user_id"),
                label = it.optString("label"),
                identityHash = it.optString("identity_hash"),
                up = it.optLong("up"),
                down = it.optLong("down"),
                enabled = if (it.has("enabled")) it.optBoolean("enabled", true) else !it.optBoolean("revoked", false),
            )
        }

    fun parseCredentials(o: JSONObject): List<DeviceCredentials> =
        o.optJSONArray("credentials").objects().map {
            DeviceCredentials(
                inboundTag = it.optString("inbound_tag"),
                protocol = it.optString("protocol"),
                link = it.optString("link"),
                qrSvg = it.optString("qr_svg"),
            )
        }

    fun parseSubscriptions(array: JSONArray): List<Subscription> =
        array.objects().map {
            Subscription(
                id = it.getString("id"),
                deviceId = it.optString("device_id").takeIf { s -> s.isNotEmpty() },
                name = it.optString("name").takeIf { s -> s.isNotEmpty() },
                url = it.optString("url"),
                qrText = it.optString("qr_text").takeIf { s -> s.isNotEmpty() } ?: it.optString("url"),
                expiresAt = it.optLong("expires_at").takeIf { _ -> it.has("expires_at") },
                managed = it.optBoolean("managed", true),
            )
        }

    fun parseDnsPolicy(o: JSONObject): DnsPolicy {
        val resolvers = o.optJSONArray("resolvers")?.let { a ->
            List(a.length()) { i ->
                (a.optJSONObject(i)?.optString("value"))?.takeIf { it.isNotEmpty() } ?: a.optString(i)
            }
        } ?: emptyList()
        return DnsPolicy(
            mode = o.optString("mode"),
            resolvers = resolvers,
            note = o.optString("note").takeIf { it.isNotEmpty() },
        )
    }

    fun parseServers(array: JSONArray): List<ServerInfo> =
        array.objects().map {
            val tunnel = it.optJSONObject("tunnel")
            ServerInfo(
                role = it.optString("role"),
                host = it.optString("host"),
                engineReachable = it.optBoolean("engine_reachable"),
                tunnelState = tunnel?.optString("state"),
                tunnelRttMs = tunnel?.optLong("rtt_ms")?.takeIf { _ -> tunnel.has("rtt_ms") },
            )
        }

    private fun JSONArray?.objects(): List<JSONObject> =
        if (this == null) emptyList() else List(length()) { getJSONObject(it) }
}
