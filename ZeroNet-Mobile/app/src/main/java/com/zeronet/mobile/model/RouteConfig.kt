package com.zeronet.mobile.model

import androidx.compose.runtime.Immutable
import org.json.JSONArray
import org.json.JSONObject

/**
 * The user's smart-routing choices for Iran/USA pairs (Design D §4, frozen
 * contract Design B §2.4).
 *
 * Persisted in `settings.json` under `route_config`; pushed to the engine
 * inside the `buildConfig` request's `routing` block (verbatim passthrough)
 * and to the live engine via `setRoutingMode` when the user changes it.
 */
@Immutable
data class RouteConfig(
    /** Leg A pin: the gateway outbound tag the engine must not switch away from (null = auto). */
    val lockedGatewayTag: String? = null,
    /** Leg B pin: the exit host the engine must not switch away from (null = auto). */
    val lockedExitHost: String? = null,
    /** Preferred gateway tags, in order (used as scorer weights). */
    val gatewayPriorities: List<String> = emptyList(),
    /** Preferred exit hosts, in order. */
    val exitPriorities: List<String> = emptyList(),
    /** Seconds between lightweight path-A probes. */
    val probeIntervalSec: Int = 60,
    /** Minimum seconds between automatic switches (anti-flap). */
    val cooldownSec: Int = 120,
    /**
     * The explicit consent escape hatch (Design B §2.5-3): when every USA
     * exit is down, allow direct traffic instead of stopping it. Default
     * off — without it, traffic stops (fail-closed), never silently reroutes.
     */
    val allowDirectWhenUsDown: Boolean = false,
) {
    /** The `routing` block of the `buildConfig` request (Design B §2.4, verbatim). */
    fun toRoutingJson(profile: ConnectionProfile): JSONObject = JSONObject()
        .put("mode", profile.wire)
        .put("pairBalancer", "pair-pool")
        .put("lockedGateway", lockedGatewayTag)
        .put("lockedExit", lockedExitHost)
        .put("priorities", JSONObject()
            .put("gateways", JSONArray(gatewayPriorities))
            .put("exits", JSONArray(exitPriorities)))
        .put("probe", JSONObject()
            .put("intervalSec", probeIntervalSec)
            .put("fullPairIntervalSec", 300)
            .put("throughputBytes", 262144)
            .put("timeoutSec", 15))
        .put("cooldownSec", cooldownSec)
        .put("switchLogSize", 32)
        .put("allowDirectWhenUsDown", allowDirectWhenUsDown)

    /** The `setRoutingMode` request (same shape, live-applied without restart). */
    fun toModeRequest(profile: ConnectionProfile, gamingActive: Boolean): JSONObject =
        toRoutingJson(profile).put("gamingActive", gamingActive).put("bootstrapActive", false)

    fun toJson(): JSONObject = JSONObject()
        .put("lockedGatewayTag", lockedGatewayTag)
        .put("lockedExitHost", lockedExitHost)
        .put("gatewayPriorities", JSONArray(gatewayPriorities))
        .put("exitPriorities", JSONArray(exitPriorities))
        .put("probeIntervalSec", probeIntervalSec)
        .put("cooldownSec", cooldownSec)
        .put("allowDirectWhenUsDown", allowDirectWhenUsDown)

    companion object {
        fun fromJson(o: JSONObject?): RouteConfig {
            val d = RouteConfig()
            if (o == null) return d
            return RouteConfig(
                lockedGatewayTag = o.optString("lockedGatewayTag").takeIf { it.isNotEmpty() },
                lockedExitHost = o.optString("lockedExitHost").takeIf { it.isNotEmpty() },
                gatewayPriorities = o.optJSONArray("gatewayPriorities")?.let { a -> List(a.length()) { a.optString(it) } } ?: d.gatewayPriorities,
                exitPriorities = o.optJSONArray("exitPriorities")?.let { a -> List(a.length()) { a.optString(it) } } ?: d.exitPriorities,
                probeIntervalSec = o.optInt("probeIntervalSec", d.probeIntervalSec).coerceIn(10, 3600),
                cooldownSec = o.optInt("cooldownSec", d.cooldownSec).coerceIn(0, 3600),
                allowDirectWhenUsDown = o.optBoolean("allowDirectWhenUsDown", d.allowDirectWhenUsDown),
            )
        }
    }
}

/**
 * How ZeroNet chooses and runs servers — extended with the six smart-routing
 * modes (Design D §4.1). [Normal] keeps its meaning and behaves as
 * [Balanced]; saved `Normal` settings keep working unchanged.
 */
enum class ConnectionProfile {
    Normal,
    Balanced,
    LowestLatency,
    MaxStability,
    Gaming,
    Manual,
    FixedUsExit,
    Fast,
    Legacy,
}

/** The mode's spelling on the wire (`routing.mode`, Design B §2.4). */
val ConnectionProfile.wire: String
    get() = when (this) {
        ConnectionProfile.Normal, ConnectionProfile.Balanced, ConnectionProfile.Legacy -> "balanced"
        ConnectionProfile.LowestLatency -> "lowest-latency"
        ConnectionProfile.MaxStability -> "max-stability"
        ConnectionProfile.Gaming -> "gaming"
        ConnectionProfile.Manual -> "manual"
        ConnectionProfile.FixedUsExit -> "fixed-us-exit"
        ConnectionProfile.Fast -> "balanced"
    }

/** Whether the profile shapes servers and evasion the way the original Normal did. */
val ConnectionProfile.classic: Boolean
    get() = this == ConnectionProfile.Normal || this == ConnectionProfile.Balanced ||
        this == ConnectionProfile.Legacy || this == ConnectionProfile.LowestLatency ||
        this == ConnectionProfile.MaxStability

/** Whether the engine's pair-aware routing applies (the `routing` block is emitted). */
val ConnectionProfile.pairAware: Boolean
    get() = when (this) {
        ConnectionProfile.Normal, ConnectionProfile.Balanced, ConnectionProfile.LowestLatency,
        ConnectionProfile.MaxStability, ConnectionProfile.Gaming, ConnectionProfile.Manual,
        ConnectionProfile.FixedUsExit -> true
        ConnectionProfile.Fast, ConnectionProfile.Legacy -> false
    }
