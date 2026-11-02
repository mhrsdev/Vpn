package com.zeronet.mobile.ui.admin

import org.json.JSONArray
import org.json.JSONObject

/**
 * Smart split-routing and Huawei-router management, against the backend's
 * `/api/v1` contract extensions.
 *
 * App-side contract proposal (for the backend agent's frozen extension; the
 * shapes below are what this UI sends and parses):
 *
 * Smart routing (the Iran gateway classifies destinations: Iranian → direct
 * Iran egress, foreign/unknown → USA tunnel; unknown defaults to USA):
 * - GET    /api/v1/routing/rules            → {version, rules:[SplitRule]}
 * - POST   /api/v1/routing/rules            {rule} → {rule}
 * - PUT    /api/v1/routing/rules/{id}       {rule} → {rule}
 * - DELETE /api/v1/routing/rules/{id}       → {ok:true}
 * - POST   /api/v1/routing/test             {target} →
 *          {route, matched_rule?, exit_country?, dns_policy?, confidence, reason}
 *
 * Huawei router (Design G: the H158-381 5G CPE as an L2TP VPN client — no
 * extra hardware; the `/api/v1/modem/` endpoint group per G §Q4):
 * - GET    /api/v1/modem/capabilities       → {model, firmware?, vpn_client:{protocols:[...], fields:[...]}, note?}
 * - GET    /api/v1/modem/accounts           → {accounts:[ModemAccount]}
 * - POST   /api/v1/modem/accounts           {name} → {account, credentials:[ModemCredential]}
 * - GET    /api/v1/modem/accounts/{id}      → {account, credentials:[ModemCredential]}
 * - POST   /api/v1/modem/accounts/{id}/rotate → {credentials:[ModemCredential]}
 * - DELETE /api/v1/modem/accounts/{id}      → {ok:true}
 * - GET    /api/v1/modem/guide?protocol=l2tp → {steps:[{title,body}]}
 * - GET    /api/v1/modem/security?protocol=l2tp → {findings:[{id,severity,title,detail}]}
 *
 * The VPN-client field list is data-driven from `capabilities`: the UI
 * renders ONLY the fields the backend declares the real H158-381 firmware
 * accepts (per G §c: LNS address, Hostname, Tunnel password, PPP user name,
 * PPP password). Nothing about the firmware is invented here.
 *
 * Pure functions only: parsing, request building, the security grades and
 * the local rule matcher are unit-tested without any backend.
 */
object RouterApi {

    // ------------------------------------------------------- smart routing

    /** One split-routing rule. `action` is "iran" (direct Iran egress) or "usa" (USA tunnel). */
    data class SplitRule(
        val id: String,
        val kind: String, // domain | ip | cidr | geoip
        val value: String,
        val action: String, // iran | usa
        val priority: Int,
        val enabled: Boolean,
        val note: String?,
    ) {
        fun toJson(): JSONObject = JSONObject()
            .put("id", id)
            .put("kind", kind)
            .put("value", value)
            .put("action", action)
            .put("priority", priority)
            .put("enabled", enabled)
            .put("note", note)

        companion object {
            fun fromJson(o: JSONObject): SplitRule = SplitRule(
                id = o.optString("id"),
                kind = o.optString("kind"),
                value = o.optString("value"),
                action = o.optString("action"),
                priority = o.optInt("priority"),
                enabled = o.optBoolean("enabled", true),
                note = o.optString("note").takeIf { it.isNotEmpty() },
            )
        }
    }

    data class RouteTestResult(
        val route: String, // iran | usa | blocked
        val matchedRule: SplitRule?,
        val exitCountry: String?,
        val dnsPolicy: String?,
        val confidence: Double,
        val reason: String,
    ) {
        companion object {
            fun fromJson(o: JSONObject): RouteTestResult = RouteTestResult(
                route = o.optString("route"),
                matchedRule = o.optJSONObject("matched_rule")?.let { SplitRule.fromJson(it) },
                exitCountry = o.optString("exit_country").takeIf { it.isNotEmpty() },
                dnsPolicy = o.optString("dns_policy").takeIf { it.isNotEmpty() },
                confidence = o.optDouble("confidence", 0.0),
                reason = o.optString("reason"),
            )
        }
    }

    fun parseSplitRules(array: JSONArray?): List<SplitRule> {
        if (array == null) return emptyList()
        return List(array.length()) { SplitRule.fromJson(array.getJSONObject(it)) }
            .sortedWith(compareBy({ it.priority }, { it.id }))
    }

    /**
     * Client-side preview matcher over the same rule list the backend holds.
     * Returns null when no local rule matches (geoip and unknown targets need
     * the backend, which is authoritative). Rules are evaluated in priority
     * order; disabled rules are skipped. Unknown targets default to the USA
     * tunnel — never to Iran egress, never to direct.
     */
    fun matchLocal(rules: List<SplitRule>, target: String): RouteTestResult? {
        val t = target.trim().lowercase()
        if (t.isEmpty()) return null
        val ordered = rules.filter { it.enabled }.sortedWith(compareBy({ it.priority }, { it.id }))
        for (rule in ordered) {
            val matched = when (rule.kind) {
                "domain" -> domainMatches(rule.value.lowercase(), t)
                "ip" -> t == rule.value.lowercase()
                "cidr" -> cidrMatches(rule.value, t)
                else -> false // geoip and future kinds: backend only
            }
            if (matched) {
                val confidence = when (rule.kind) {
                    "domain" -> if (t == rule.value.lowercase()) 1.0 else 0.9
                    "cidr" -> 0.95
                    else -> 1.0
                }
                return RouteTestResult(
                    route = rule.action,
                    matchedRule = rule,
                    exitCountry = if (rule.action == "usa") "US" else "IR",
                    dnsPolicy = null,
                    confidence = confidence,
                    reason = "local preview: matched rule \"${rule.value}\"",
                )
            }
        }
        return null
    }

    /** Exact or parent-domain match (`bank.ir` matches `www.bank.ir`, not `notbank.ir`). */
    internal fun domainMatches(rule: String, target: String): Boolean {
        if (rule.isEmpty()) return false
        val r = rule.trimStart('.')
        return target == r || target.endsWith(".$r")
    }

    /** IPv4 CIDR match; anything unparsable never matches (fail-closed). */
    internal fun cidrMatches(cidr: String, target: String): Boolean {
        val parts = cidr.split("/")
        if (parts.size != 2) return false
        val bits = parts[1].toIntOrNull() ?: return false
        if (bits !in 0..32) return false
        val net = ipToInt(parts[0]) ?: return false
        val addr = ipToInt(target) ?: return false
        val mask = if (bits == 0) 0 else (-1 shl (32 - bits))
        return (net and mask) == (addr and mask)
    }

    private fun ipToInt(ip: String): Int? {
        val p = ip.split(".")
        if (p.size != 4) return null
        val nums = p.map { it.toIntOrNull() ?: return null }
        if (nums.any { it !in 0..255 }) return null
        return (nums[0] shl 24) or (nums[1] shl 16) or (nums[2] shl 8) or nums[3]
    }

    // ------------------------------------------------------- huawei router
    // Design G: H158-381 (5G CPE Pro 5) stock firmware has a VPN CLIENT with
    // L2TP + PPTP ONLY (CONFIRMED, Huawei doc en-us00761349). PPTP is refused
    // on principle (broken crypto — not offered, only explained). Plain L2TP
    // is WEAK (no trustworthy confidentiality); the server mandates MPPE-128
    // fail-closed, and the panel requires informed consent before showing
    // credentials. The modem link is NEVER called "secure" unqualified.

    /** Honest security grades for modem VPN-client protocols. Never upgraded. */
    enum class SecurityGrade { NOT_AVAILABLE, REFUSED, WEAK, UNTRUSTWORTHY, OK }

    data class ProtocolSecurity(
        val protocol: String,
        val grade: SecurityGrade,
        val label: String,
        val detail: String,
        /** Whether the panel may offer this protocol as a choice at all. */
        val offerable: Boolean,
    )

    /**
     * The honest table, verbatim from Design G §d. PPTP is refused (shown only
     * as an explained absence); plain L2TP is WEAK with informed consent;
     * anything the firmware has no evidence for is NOT AVAILABLE — never
     * invented, never labeled secure.
     */
    fun protocolSecurity(protocol: String): ProtocolSecurity = when (protocol.lowercase()) {
        "pptp" -> ProtocolSecurity(
            protocol, SecurityGrade.REFUSED, "Refused — not offered",
            "PPTP's encryption (MPPE/RC4 with MS-CHAPv2) is broken and can be decrypted by a determined attacker. This panel does not generate PPTP credentials.",
            offerable = false,
        )
        "l2tp" -> ProtocolSecurity(
            protocol, SecurityGrade.WEAK, "Weak",
            "L2TP by itself provides no encryption. With the mandatory MPPE-128 setting, traffic between the modem and the server gets RC4-based encryption: it defeats casual snooping but NOT a determined network observer. It is not modern-VPN-grade — use it with eyes open. It is far better than no VPN, and it is the only protocol this modem's stock firmware offers.",
            offerable = true,
        )
        else -> ProtocolSecurity(
            protocol, SecurityGrade.NOT_AVAILABLE, "Not available",
            "No public evidence that the H158-381 stock firmware supports \"$protocol\". It is not offered because it does not exist — not because it was omitted.",
            offerable = false,
        )
    }

    /**
     * The exact L2TP field ids of the H158-381 VPN-client form (Design G §c,
     * from Huawei doc en-us00761349), in form order. The backend supplies the
     * values; the app renders only these — never invented fields.
     */
    val l2tpFieldOrder = listOf(
        "connection_type", // fixed "L2TP VPN client", not editable
        "lns_address",
        "hostname",
        "tunnel_password",
        "ppp_username",
        "ppp_password",
    )

    /** One VPN-client field the firmware accepts — declared by the backend, never hardcoded. */
    data class VpnClientField(
        val id: String,
        val label: String,
        val kind: String, // text | password | choice
        val options: List<String>,
        val required: Boolean,
        val sensitive: Boolean,
    ) {
        companion object {
            fun fromJson(o: JSONObject): VpnClientField = VpnClientField(
                id = o.getString("id"),
                label = o.optString("label").takeIf { it.isNotEmpty() } ?: o.getString("id"),
                kind = o.optString("kind", "text"),
                options = o.optJSONArray("options")?.let { a -> List(a.length()) { a.optString(it) } } ?: emptyList(),
                required = o.optBoolean("required"),
                sensitive = o.optBoolean("sensitive") || o.optString("kind") == "password",
            )
        }
    }

    data class ModemCapabilities(
        val model: String,
        val firmware: String?,
        val vpnClientProtocols: List<String>,
        val fields: List<VpnClientField>,
        val note: String?,
    ) {
        companion object {
            fun fromJson(o: JSONObject): ModemCapabilities {
                val vpn = o.optJSONObject("vpn_client")
                return ModemCapabilities(
                    model = o.optString("model").takeIf { it.isNotEmpty() } ?: "Unknown modem",
                    firmware = o.optString("firmware").takeIf { it.isNotEmpty() },
                    vpnClientProtocols = vpn?.optJSONArray("protocols")?.let { a -> List(a.length()) { a.optString(it) } } ?: emptyList(),
                    fields = vpn?.optJSONArray("fields")?.let { a -> List(a.length()) { VpnClientField.fromJson(a.getJSONObject(it)) } } ?: emptyList(),
                    note = o.optString("note").takeIf { it.isNotEmpty() },
                )
            }
        }
    }

    /** One modem account: an independent PPP identity (`h158-…`), revocable on its own. */
    data class ModemAccount(
        val id: String,
        val name: String,
        val username: String,
        val status: String, // connected | last_seen | never
        val lastSeen: String?,
        val dataUsed: Long,
    ) {
        companion object {
            fun fromJson(o: JSONObject): ModemAccount = ModemAccount(
                id = o.optString("id"),
                name = o.optString("name").takeIf { it.isNotEmpty() } ?: o.optString("username"),
                username = o.optString("username"),
                status = o.optString("status").takeIf { it.isNotEmpty() } ?: "never",
                lastSeen = o.optString("last_seen").takeIf { it.isNotEmpty() },
                dataUsed = o.optLong("data_used"),
            )
        }
    }

    fun parseModemAccounts(array: JSONArray?): List<ModemAccount> {
        if (array == null) return emptyList()
        return List(array.length()) { ModemAccount.fromJson(array.getJSONObject(it)) }
    }

    /** One credential value to copy into the modem's VPN-client UI. */
    data class ModemCredential(
        val fieldId: String,
        val label: String,
        val value: String,
        val sensitive: Boolean,
    ) {
        companion object {
            fun fromJson(o: JSONObject): ModemCredential = ModemCredential(
                fieldId = o.optString("field_id"),
                label = o.optString("label").takeIf { it.isNotEmpty() } ?: o.optString("field_id"),
                value = o.optString("value"),
                sensitive = o.optBoolean("sensitive", true),
            )
        }
    }

    /**
     * Orders credentials the way the modem's form asks for them
     * ([l2tpFieldOrder]); unknown field ids trail at the end rather than
     * being dropped or reordered into the firmware's face.
     */
    fun orderCredentials(creds: List<ModemCredential>): List<ModemCredential> {
        val rank = l2tpFieldOrder.withIndex().associate { it.value to it.index }
        return creds.sortedBy { rank[it.fieldId] ?: Int.MAX_VALUE }
    }

    fun parseModemCredentials(array: JSONArray?): List<ModemCredential> {
        if (array == null) return emptyList()
        return orderCredentials(List(array.length()) { ModemCredential.fromJson(array.getJSONObject(it)) })
    }

    data class GuideStep(val title: String, val body: String) {
        companion object {
            fun fromJson(o: JSONObject): GuideStep = GuideStep(
                title = o.optString("title"),
                body = o.optString("body"),
            )
        }
    }

    /** A security finding about the modem setup. Severity is the backend's word — the UI never upgrades it. */
    data class SecurityFinding(
        val id: String,
        val severity: String, // insecure | untrustworthy | warning | ok
        val title: String,
        val detail: String,
    ) {
        companion object {
            fun fromJson(o: JSONObject): SecurityFinding = SecurityFinding(
                id = o.optString("id"),
                severity = o.optString("severity").takeIf { it.isNotEmpty() } ?: "warning",
                title = o.optString("title"),
                detail = o.optString("detail"),
            )
        }
    }

    fun parseGuideSteps(array: JSONArray?): List<GuideStep> {
        if (array == null) return emptyList()
        return List(array.length()) { GuideStep.fromJson(array.getJSONObject(it)) }
    }

    fun parseSecurityFindings(array: JSONArray?): List<SecurityFinding> {
        if (array == null) return emptyList()
        val order = mapOf("insecure" to 0, "untrustworthy" to 1, "warning" to 2, "ok" to 3)
        return List(array.length()) { SecurityFinding.fromJson(array.getJSONObject(it)) }
            .sortedBy { order[it.severity] ?: 2 }
    }

    /** Human-readable byte count for per-account usage. */
    fun formatBytes(bytes: Long): String {
        if (bytes < 1024) return "$bytes B"
        val units = arrayOf("KB", "MB", "GB", "TB")
        var v = bytes.toDouble() / 1024
        var u = 0
        while (v >= 1024 && u < units.size - 1) { v /= 1024; u++ }
        return "%.1f %s".format(v, units[u])
    }
}
