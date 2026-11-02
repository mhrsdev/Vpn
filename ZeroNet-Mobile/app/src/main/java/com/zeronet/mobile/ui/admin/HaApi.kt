package com.zeronet.mobile.ui.admin

import org.json.JSONArray
import org.json.JSONObject

/**
 * Inter-server High Availability (owner HA addendum, binding): the Iran→USA
 * leg runs DUAL ALWAYS-ON — Tunnel A (primary) + Tunnel B (hot standby),
 * both connected/authenticated/ready with independent keepalives; two
 * transport families preferred (WireGuard primary + fallback); fast
 * detection (configurable heartbeat 2–5s, loss/RTT/jitter/timeout) with
 * anti-flap; switchover without new connection setup; auto-recovery with
 * health probing before promotion, no flap-back; both-down → foreign
 * fail-closed, Iranian may continue; fixed USA exit IP (transport-level
 * failover only).
 *
 * Honesty is load-bearing here: the panel shows MEASURED downtime and the
 * 3-level distinction (fast switch for new connections / session
 * preservation / true lossless) — never "zero downtime" without measured
 * proof. Active-active is INVESTIGATED, not assumed: the backend declares
 * which modes it actually supports and the UI only offers those.
 *
 * App-side contract proposal (for the backend agent's frozen HA extension):
 * - GET  /api/v1/ha/status   → {tunnels:[HaTunnel], primary, mode,
 *                              available_modes:[...], auto_recovery,
 *                              heartbeat_interval_s, failover_threshold_missed,
 *                              last_failover_at, failover_count,
 *                              total_downtime_s, recent_failovers:[...],
 *                              exit:{...}}
 * - POST /api/v1/ha/primary  {tunnel:"A"|"B"} → {ok, primary}
 * - POST /api/v1/ha/mode     {mode} → {ok, mode}
 * - POST /api/v1/ha/settings {heartbeat_interval_s?, failover_threshold_missed?,
 *                              auto_recovery?} → {ok, ...}
 *
 * Pure functions only: parsing and formatting are unit-tested without any backend.
 */
object HaApi {

    /** One inter-server tunnel. `state`: up | degraded | standby | down. */
    data class HaTunnel(
        val id: String, // A | B
        val protocol: String, // wireguard | ...
        val transportFamily: String?,
        val state: String,
        val rttMs: Long?,
        val lossPct: Double?,
        val jitterMs: Long?,
        val keepaliveOk: Boolean,
        val lastHeartbeatAt: Long, // epoch millis, 0 = unknown
        val bytesUp: Long,
        val bytesDown: Long,
    ) {
        val isPrimaryCandidate: Boolean get() = state == "up" || state == "degraded" || state == "standby"

        companion object {
            fun fromJson(o: JSONObject): HaTunnel = HaTunnel(
                id = o.optString("id"),
                protocol = o.optString("protocol"),
                transportFamily = o.optString("transport_family").takeIf { it.isNotEmpty() },
                state = o.optString("state").takeIf { it.isNotEmpty() } ?: "down",
                rttMs = o.optLong("rtt_ms").takeIf { o.has("rtt_ms") },
                lossPct = o.optDouble("loss_pct").takeIf { o.has("loss_pct") },
                jitterMs = o.optLong("jitter_ms").takeIf { o.has("jitter_ms") },
                keepaliveOk = o.optBoolean("keepalive_ok"),
                lastHeartbeatAt = o.optLong("last_heartbeat_at"),
                bytesUp = o.optLong("bytes_up"),
                bytesDown = o.optLong("bytes_down"),
            )
        }
    }

    /** One failover event, with what was actually measured — not marketing. */
    data class HaFailoverEvent(
        val at: Long, // epoch millis
        val from: String,
        val to: String,
        val reason: String,
        val downtimeS: Double,
        val sessionsPreservedPct: Double?,
    ) {
        companion object {
            fun fromJson(o: JSONObject): HaFailoverEvent = HaFailoverEvent(
                at = o.optLong("at"),
                from = o.optString("from"),
                to = o.optString("to"),
                reason = o.optString("reason"),
                downtimeS = o.optDouble("downtime_s"),
                sessionsPreservedPct = o.optDouble("sessions_preserved_pct").takeIf { o.has("sessions_preserved_pct") },
            )
        }
    }

    /** The fixed USA exit as seen through the HA leg. */
    data class HaExit(
        val ip: String,
        val country: String?,
        val healthy: Boolean,
        val checkedAt: Long,
        val ipStable: Boolean, // unchanged across failovers (transport-level failover only)
    ) {
        companion object {
            fun fromJson(o: JSONObject): HaExit = HaExit(
                ip = o.optString("ip"),
                country = o.optString("country").takeIf { it.isNotEmpty() },
                healthy = o.optBoolean("healthy"),
                checkedAt = o.optLong("checked_at"),
                ipStable = o.optBoolean("ip_stable", true),
            )
        }
    }

    data class HaStatus(
        val tunnels: List<HaTunnel>,
        val primary: String?,
        val mode: String, // hot_standby | active_active
        val availableModes: List<String>,
        val autoRecovery: Boolean,
        val heartbeatIntervalS: Int,
        val failoverThresholdMissed: Int,
        val lastFailoverAt: Long,
        val failoverCount: Long,
        val totalDowntimeS: Double,
        val recentFailovers: List<HaFailoverEvent>,
        val exit: HaExit?,
    ) {
        fun tunnel(id: String): HaTunnel? = tunnels.firstOrNull { it.id == id }

        companion object {
            fun fromJson(o: JSONObject): HaStatus = HaStatus(
                tunnels = o.optJSONArray("tunnels")?.let { a -> List(a.length()) { HaTunnel.fromJson(a.getJSONObject(it)) } } ?: emptyList(),
                primary = o.optString("primary").takeIf { it.isNotEmpty() },
                mode = o.optString("mode").takeIf { it.isNotEmpty() } ?: "hot_standby",
                availableModes = o.optJSONArray("available_modes")?.let { a -> List(a.length()) { a.optString(it) } } ?: listOf("hot_standby"),
                autoRecovery = o.optBoolean("auto_recovery", true),
                heartbeatIntervalS = o.optInt("heartbeat_interval_s", 3),
                failoverThresholdMissed = o.optInt("failover_threshold_missed", 3),
                lastFailoverAt = o.optLong("last_failover_at"),
                failoverCount = o.optLong("failover_count"),
                totalDowntimeS = o.optDouble("total_downtime_s"),
                recentFailovers = o.optJSONArray("recent_failovers")?.let { a -> List(a.length()) { HaFailoverEvent.fromJson(a.getJSONObject(it)) } } ?: emptyList(),
                exit = o.optJSONObject("exit")?.let { HaExit.fromJson(it) },
            )
        }
    }

    fun parseTunnels(array: JSONArray?): List<HaTunnel> {
        if (array == null) return emptyList()
        return List(array.length()) { HaTunnel.fromJson(array.getJSONObject(it)) }
    }

    /** Measured downtime, human-readable. Never claims zero without measurement. */
    fun formatDowntime(seconds: Double): String {
        if (seconds < 0) return "—"
        val total = seconds.toLong()
        if (total < 60) return "${total}s"
        val m = total / 60
        if (m < 60) {
            val s = total % 60
            return if (s == 0L) "${m}m" else "${m}m ${s}s"
        }
        val h = m / 60
        val mm = m % 60
        return if (mm == 0L) "${h}h" else "${h}h ${mm}m"
    }

    /** Relative time; `nowMillis` is a parameter so tests don't depend on the clock. */
    fun formatAgo(epochMillis: Long, nowMillis: Long): String {
        if (epochMillis <= 0) return "never"
        val d = nowMillis - epochMillis
        if (d < 0) return "—"
        if (d < 60_000) return "just now"
        val m = d / 60_000
        if (m < 60) return "$m min ago"
        val h = m / 60
        if (h < 24) return "$h h ago"
        return "${h / 24} d ago"
    }

    fun formatBytes(bytes: Long): String = RouterApi.formatBytes(bytes)

    /** Mode label; unknown modes are shown as-is, never silently mapped. */
    fun modeLabel(mode: String): String = when (mode) {
        "hot_standby" -> "Hot standby"
        "active_active" -> "Active-active"
        else -> mode
    }
}
