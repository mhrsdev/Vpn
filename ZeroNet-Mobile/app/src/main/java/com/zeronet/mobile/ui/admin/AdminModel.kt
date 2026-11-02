package com.zeronet.mobile.ui.admin

import android.content.Context
import androidx.compose.runtime.Stable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import com.zeronet.mobile.core.NativeExtras
import com.zeronet.mobile.data.MyServerStore
import com.zeronet.mobile.model.RouteEvent
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject

/** The admin sheet's sections. */
sealed interface AdminScreen {
    data object Dashboard : AdminScreen
    data object Users : AdminScreen
    data object Devices : AdminScreen
    data object Subscriptions : AdminScreen
    data object RouteHistory : AdminScreen
    data object Dns : AdminScreen
    data object Backup : AdminScreen
    data object HuaweiRouter : AdminScreen
    data object SmartRouting : AdminScreen
    data object Ha : AdminScreen
}

/**
 * State and actions for the management UI (Design D §3, Design C `/api/v1`).
 *
 * Everything goes through [run] — [NativeExtras.adminCallFlow] in the app,
 * scripted in tests. The admin bearer <redacted> comes from the open pair's
 * record (delivered once at provision time, encrypted at rest) and is
 * attached per call; it is never stored anywhere new and never logged.
 */
@Stable
class AdminModel(
    private val context: Context,
    private val scope: CoroutineScope,
    private val run: (JSONObject) -> Flow<JSONObject> = NativeExtras::adminCallFlow,
    private val notify: (String) -> Unit = {},
    val copy: (text: String, sensitive: Boolean) -> Unit = { _, _ -> },
    val startIntent: (android.content.Intent) -> Unit = {},
) {
    private val store = MyServerStore.get(context)

    var open by mutableStateOf(false)
    var screen by mutableStateOf<AdminScreen>(AdminScreen.Dashboard)
        private set
    var pairId by mutableStateOf<String?>(null)
        private set
    var loading by mutableStateOf(false)
    var error by mutableStateOf<String?>(null)

    val servers = mutableStateListOf<AdminApi.ServerInfo>()
    var statusJson by mutableStateOf<JSONObject?>(null)
    var exitIp by mutableStateOf<String?>(null)
    var usageSummary by mutableStateOf<JSONObject?>(null)
    val users = mutableStateListOf<AdminApi.AdminUser>()
    val devices = mutableStateListOf<AdminApi.AdminDevice>()
    val subscriptions = mutableStateListOf<AdminApi.Subscription>()
    val routeEvents = mutableStateListOf<RouteEvent>()
    var dnsPolicy by mutableStateOf<AdminApi.DnsPolicy?>(null)
    var lastCredentials by mutableStateOf<List<AdminApi.DeviceCredentials>?>(null)
    var backupBlob by mutableStateOf<String?>(null)
    var qrText by mutableStateOf<String?>(null)

    // Huawei router (the H158-381 modem as an L2TP VPN client — Design G).
    var modemCaps by mutableStateOf<RouterApi.ModemCapabilities?>(null)
    val modemAccounts = mutableStateListOf<RouterApi.ModemAccount>()
    var selectedModemAccount by mutableStateOf<RouterApi.ModemAccount?>(null)
        private set
    val modemCredentials = mutableStateListOf<RouterApi.ModemCredential>()
    var modemCredProtocol by mutableStateOf<String?>(null)
    /** Informed consent (Design G §d): explicit per-session opt-in before any credential is shown. */
    var modemConsent by mutableStateOf(false)
    val guideSteps = mutableStateListOf<RouterApi.GuideStep>()
    val securityFindings = mutableStateListOf<RouterApi.SecurityFinding>()

    // Smart split-routing (gateway-side destination classification).
    val splitRules = mutableStateListOf<RouterApi.SplitRule>()
    var rulesVersion by mutableStateOf<String?>(null)
    var editingRule by mutableStateOf<RouterApi.SplitRule?>(null)
    var testTarget by mutableStateOf("")
    var testResult by mutableStateOf<RouterApi.RouteTestResult?>(null)
    var testLocalPreview by mutableStateOf<RouterApi.RouteTestResult?>(null)

    // Inter-server high availability (Iran→USA dual always-on leg).
    var haStatus by mutableStateOf<HaApi.HaStatus?>(null)

    private var job: Job? = null
    private var token: String? = null

    // ------------------------------------------------------------ navigation

    fun open(id: String) {
        pairId = id
        screen = AdminScreen.Dashboard
        open = true
        scope.launch {
            token = withContext(Dispatchers.IO) {
                store.pairs().firstOrNull { it.pairId == id }?.adminToken
            }
            refreshDashboard()
        }
    }

    fun close() {
        job?.cancel()
        token = null
        open = false
        // Consent is per-session: the next open asks again before any credential is shown.
        modemConsent = false
        clearModemCredentials()
    }

    fun go(s: AdminScreen) {
        screen = s
        error = null
        when (s) {
            AdminScreen.Dashboard -> refreshDashboard()
            AdminScreen.Users -> refreshUsers()
            AdminScreen.Devices -> { devices.clear(); refreshUsers() }
            AdminScreen.Subscriptions -> refreshSubscriptions()
            AdminScreen.RouteHistory -> refreshRouteHistory()
            AdminScreen.Dns -> refreshDns()
            AdminScreen.Backup -> Unit
            AdminScreen.HuaweiRouter -> refreshRouterCaps()
            AdminScreen.SmartRouting -> refreshSplitRules()
            AdminScreen.Ha -> refreshHa()
        }
    }

    // ------------------------------------------------------------------ plumbing

    /**
     * One management call. Returns the `done` event's payload (`ok:true`),
     * or null after surfacing the error.
     *
     * The request carries the open pair's record so the native side can SSH
     * to the target server's loopback admin API (Design D §5.1); the bearer
     * <redacted> per call from memory, never persisted.
     */
    private suspend fun api(method: String, path: String, query: JSONObject? = null, body: JSONObject? = null, target: String = "exit"): JSONObject? {
        // A pair made before the panel existed has no token: put the current
        // server program and the panel on it once, keep the token, go on.
        if (token.isNullOrEmpty()) upgradePair()
        val t = token
        if (t.isNullOrEmpty()) return null
        val id = pairId
        val pairRecord = withContext(Dispatchers.IO) {
            store.pairs().firstOrNull { it.pairId == id }?.record
        }
        if (pairRecord == null) {
            error = "No pair record for this pair (re-provision to enable the admin panel)."
            return null
        }
        val request = AdminApi.request(method, path, query, body)
            .put("pair_id", pairId)
            .put("token", t)
            .put("pair_record", pairRecord)
            .put("target", target)
        var last = JSONObject().put("t", "done").put("ok", false).put("error", "cancelled")
        run(request).collect { e -> if (e.optString("t") == "done") last = e }
        if (!last.optBoolean("ok")) {
            // The token must never surface in the UI, even if the backend
            // echoes it inside an error string (defense in depth, F W1).
            error = last.optString("error").replace(t, "•••")
            return null
        }
        return last
    }

    /** Progress text while an older pair is being upgraded (shown in place of the error). */
    var upgrading by mutableStateOf<String?>(null)
        private set

    /**
     * Install the operator panel (and the current server program) on a pair an
     * older version made. Its config, keys and users are kept; the gateway's
     * server program restarts, so connections drop for a few seconds.
     */
    private suspend fun upgradePair() {
        val id = pairId ?: return
        val entry = withContext(Dispatchers.IO) { store.pairs().firstOrNull { it.pairId == id } }
        if (entry == null) {
            error = "No pair record for this pair (re-provision to enable the admin panel)."
            return
        }
        val dir = com.zeronet.mobile.ui.myserver.ServerProgram.dir(context)
        if (dir == null) {
            error = "This build has no panel program to install."
            return
        }
        upgrading = "Installing the management panel on the server…"
        val request = JSONObject()
            .put("op", "upgrade_pair")
            .put("pair_record", entry.record)
            .put("local_binary_dir", dir)
        var last = JSONObject().put("t", "done").put("ok", false).put("error", "cancelled")
        try {
            run(request).collect { e ->
                when (e.optString("t")) {
                    "detail" -> upgrading = e.optString("text")
                    "done" -> last = e
                }
            }
        } finally {
            upgrading = null
        }
        if (!last.optBoolean("ok")) {
            error = last.optString("error")
            return
        }
        val fresh = last.optString("admin_token").takeIf { it.isNotEmpty() }
        if (fresh == null) {
            error = "The server did not return a panel token."
            return
        }
        withContext(Dispatchers.IO) { store.putPair(entry.copy(adminToken = fresh)) }
        token = fresh
    }

    private fun launch(block: suspend () -> Unit) {
        job?.cancel()
        loading = true
        error = null
        job = scope.launch {
            try {
                block()
            } finally {
                loading = false
            }
        }
    }

    // -------------------------------------------------------------- dashboard

    fun refreshDashboard() = launch {
        api("GET", "/api/v1/status")?.let { statusJson = it }
        api("GET", "/api/v1/servers")?.let { servers.clear(); servers.addAll(AdminApi.parseServers(it.optJSONArray("servers") ?: JSONArray())) }
        api("GET", "/api/v1/usage/summary")?.let { usageSummary = it }
        api("GET", "/api/v1/net/exit-ip")?.let { exitIp = it.optString("ip").takeIf { s -> s.isNotEmpty() } }
    }

    // ------------------------------------------------------------------ users

    fun refreshUsers() = launch {
        api("GET", "/api/v1/users")?.let {
            users.clear()
            users.addAll(AdminApi.parseUsers(it.optJSONArray("users") ?: JSONArray()))
        }
    }

    fun createUser(name: String, quotaGb: Long?, speedMbps: Int?, maxDevices: Int?) = launch {
        val body = JSONObject().put("name", name)
        quotaGb?.let { body.put("quota_bytes", it * 1_000_000_000L) }
        speedMbps?.let { body.put("quota_mbps", it) }
        maxDevices?.let { body.put("max_devices", it) }
        if (api("POST", "/api/v1/users", body = body) != null) refreshUsers()
    }

    fun setUserEnabled(user: AdminApi.AdminUser, enabled: Boolean) = launch {
        val op = if (enabled) "restore" else "revoke"
        if (api("POST", "/api/v1/users/${user.id}/$op") != null) refreshUsers()
    }

    fun deleteUser(user: AdminApi.AdminUser) = launch {
        if (api("DELETE", "/api/v1/users/${user.id}") != null) refreshUsers()
    }

    // ---------------------------------------------------------------- devices

    fun refreshDevices(userId: String) = launch {
        api("GET", "/api/v1/users/$userId/devices")?.let {
            devices.clear()
            devices.addAll(AdminApi.parseDevices(it.optJSONArray("devices") ?: JSONArray()))
        }
    }

    /** Issue a device: the response carries the credentials once — show them as QR immediately. */
    fun issueDevice(userId: String, label: String) = launch {
        val done = api("POST", "/api/v1/users/$userId/devices", body = JSONObject().put("label", label))
        if (done != null) {
            lastCredentials = AdminApi.parseCredentials(done.getJSONObject("device"))
            refreshDevices(userId)
        }
    }

    fun reissueDevice(device: AdminApi.AdminDevice) = launch {
        val done = api("POST", "/api/v1/devices/${device.id}/reissue")
        if (done != null) lastCredentials = AdminApi.parseCredentials(done.getJSONObject("device"))
    }

    fun revokeDevice(device: AdminApi.AdminDevice) = launch {
        if (api("POST", "/api/v1/devices/${device.id}/revoke") != null) refreshDevices(device.userId)
    }

    fun clearCredentials() {
        lastCredentials = null
    }

    // ---------------------------------------------------------- subscriptions

    fun refreshSubscriptions() = launch {
        api("GET", "/api/v1/subscriptions")?.let {
            subscriptions.clear()
            subscriptions.addAll(AdminApi.parseSubscriptions(it.optJSONArray("subscriptions") ?: JSONArray()))
        }
    }

    fun createPersonalSubscription(deviceId: String, expiresAt: Long?) = launch {
        val body = JSONObject().put("device_id", deviceId)
        expiresAt?.let { body.put("expires_at", it) }
        val done = api("POST", "/api/v1/subscriptions/personal", body = body)
        if (done != null) {
            qrText = done.optString("qr_text").takeIf { it.isNotEmpty() } ?: done.optString("url")
            refreshSubscriptions()
        }
    }

    /** Import an external subscription: the app already holds the body text (Design C §3.1). */
    fun importExternalSubscription(name: String, bodyText: String) = launch {
        val done = api("POST", "/api/v1/subscriptions/external",
            body = JSONObject().put("name", name).put("body_text", bodyText))
        if (done != null) refreshSubscriptions()
    }

    fun rotateSubscription(sub: AdminApi.Subscription) = launch {
        if (api("POST", "/api/v1/subscriptions/${sub.id}/rotate") != null) refreshSubscriptions()
    }

    fun revokeSubscription(sub: AdminApi.Subscription) = launch {
        if (api("POST", "/api/v1/subscriptions/${sub.id}/revoke") != null) refreshSubscriptions()
    }

    // ------------------------------------------------------------ route history

    fun refreshRouteHistory() = launch {
        val done = api("GET", "/api/v1/events",
            query = JSONObject().put("kind", "route").put("limit", 50))
        if (done != null) {
            routeEvents.clear()
            routeEvents.addAll(
                (done.optJSONArray("events") ?: JSONArray()).let { a ->
                    List(a.length()) { a.getJSONObject(it) }.map { RouteEvent.fromJson(it) }
                }.sortedByDescending { it.at },
            )
        }
    }

    // -------------------------------------------------------------------- dns

    fun refreshDns() = launch {
        api("GET", "/api/v1/settings/dns")?.let { dnsPolicy = AdminApi.parseDnsPolicy(it) }
    }

    fun saveDns(mode: String, resolvers: List<String>) = launch {
        val body = JSONObject().put("mode", mode)
            .put("resolvers", JSONArray(resolvers))
        if (api("PUT", "/api/v1/settings/dns", body = body) != null) refreshDns()
    }

    // ----------------------------------------------------------------- backup

    fun backup(passphrase: String) = launch {
        val done = api("POST", "/api/v1/backup", body = JSONObject().put("passphrase", passphrase))
        if (done != null) backupBlob = done.optString("blob").takeIf { it.isNotEmpty() }
    }

    fun clearBackup() {
        backupBlob = null
    }

    fun restore(backupFileBase64: String, passphrase: String) = launch {
        api("POST", "/api/v1/restore",
            body = JSONObject().put("file", backupFileBase64).put("passphrase", passphrase))
    }

    // ------------------------------------------------------- huawei router

    /**
     * What the real H158-381 firmware accepts as VPN-client settings —
     * declared by the backend (Design G: L2TP + PPTP only, PPTP refused).
     * Until the backend publishes it, the section shows an honest empty state.
     */
    fun refreshRouterCaps() = launch {
        api("GET", "/api/v1/modem/capabilities")?.let {
            modemCaps = RouterApi.ModemCapabilities.fromJson(it)
        }
        refreshModemAccounts()
    }

    fun refreshModemAccounts() = launch {
        val done = api("GET", "/api/v1/modem/accounts")
        if (done != null) {
            modemAccounts.clear()
            modemAccounts.addAll(RouterApi.parseModemAccounts(done.optJSONArray("accounts")))
            selectedModemAccount?.let { sel ->
                selectedModemAccount = modemAccounts.firstOrNull { it.id == sel.id }
            }
        }
    }

    fun selectModemAccount(account: RouterApi.ModemAccount?) {
        selectedModemAccount = account
        clearModemCredentials()
    }

    /** Create a modem account; credentials arrive only with informed consent given. */
    fun createModemAccount(name: String) = launch {
        val trimmed = name.trim()
        if (trimmed.isEmpty() || !modemConsent) return@launch
        val done = api("POST", "/api/v1/modem/accounts", body = JSONObject().put("name", trimmed))
        if (done != null) {
            done.optJSONObject("account")?.let { RouterApi.ModemAccount.fromJson(it) }?.let { acc ->
                refreshModemAccounts()
                selectedModemAccount = acc
            }
            modemCredProtocol = "l2tp"
            modemCredentials.clear()
            modemCredentials.addAll(RouterApi.parseModemCredentials(done.optJSONArray("credentials")))
        }
    }

    /** Reveal an existing account's credentials — consent-gated, never cached beyond the sheet. */
    fun revealModemCredentials(account: RouterApi.ModemAccount) = launch {
        if (!modemConsent) return@launch
        val done = api("GET", "/api/v1/modem/accounts/${account.id}")
        if (done != null) {
            modemCredProtocol = "l2tp"
            modemCredentials.clear()
            modemCredentials.addAll(RouterApi.parseModemCredentials(done.optJSONArray("credentials")))
            selectedModemAccount = account
        }
    }

    fun rotateModemPassword(account: RouterApi.ModemAccount) = launch {
        if (!modemConsent) return@launch
        val done = api("POST", "/api/v1/modem/accounts/${account.id}/rotate")
        if (done != null) {
            modemCredProtocol = "l2tp"
            modemCredentials.clear()
            modemCredentials.addAll(RouterApi.parseModemCredentials(done.optJSONArray("credentials")))
            notify("Password rotated")
        }
    }

    fun revokeModemAccount(account: RouterApi.ModemAccount) = launch {
        if (api("DELETE", "/api/v1/modem/accounts/${account.id}") != null) {
            if (selectedModemAccount?.id == account.id) selectModemAccount(null)
            refreshModemAccounts()
            notify("Modem account revoked")
        }
    }

    fun clearModemCredentials() {
        modemCredentials.clear()
        modemCredProtocol = null
    }

    fun refreshGuide(protocol: String) = launch {
        val done = api("GET", "/api/v1/modem/guide", query = JSONObject().put("protocol", protocol))
        if (done != null) {
            guideSteps.clear()
            guideSteps.addAll(RouterApi.parseGuideSteps(done.optJSONArray("steps")))
        }
    }

    fun refreshRouterSecurity(protocol: String) = launch {
        val done = api("GET", "/api/v1/modem/security", query = JSONObject().put("protocol", protocol))
        if (done != null) {
            securityFindings.clear()
            securityFindings.addAll(RouterApi.parseSecurityFindings(done.optJSONArray("findings")))
        }
    }

    // ------------------------------------------------------- smart routing

    fun refreshSplitRules() = launch {
        val done = api("GET", "/api/v1/routing/rules")
        if (done != null) {
            rulesVersion = done.optString("version").takeIf { it.isNotEmpty() }
            splitRules.clear()
            splitRules.addAll(RouterApi.parseSplitRules(done.optJSONArray("rules")))
        }
    }

    /** Create (id blank) or update a split-routing rule. */
    fun saveSplitRule(rule: RouterApi.SplitRule) = launch {
        val done = if (rule.id.isEmpty()) {
            api("POST", "/api/v1/routing/rules", body = rule.toJson())
        } else {
            api("PUT", "/api/v1/routing/rules/${rule.id}", body = rule.toJson())
        }
        if (done != null) {
            editingRule = null
            refreshSplitRules()
        }
    }

    fun deleteSplitRule(rule: RouterApi.SplitRule) = launch {
        if (api("DELETE", "/api/v1/routing/rules/${rule.id}") != null) refreshSplitRules()
    }

    fun setRuleEnabled(rule: RouterApi.SplitRule, enabled: Boolean) = launch {
        if (api("PUT", "/api/v1/routing/rules/${rule.id}", body = rule.copy(enabled = enabled).toJson()) != null) {
            refreshSplitRules()
        }
    }

    /**
     * The authoritative test: the gateway classifies [target] and reports the
     * route, the matched rule, the exit country, the DNS policy and its
     * confidence. Unknown targets default to the USA tunnel (never Iran
     * egress, never direct).
     */
    fun testRoute(target: String) = launch {
        testTarget = target
        testResult = null
        val done = api("POST", "/api/v1/routing/test", body = JSONObject().put("target", target))
        if (done != null) testResult = RouterApi.RouteTestResult.fromJson(done)
    }

    /** Instant client-side preview over the same rule list (the backend stays authoritative). */
    fun previewRoute(target: String) {
        testLocalPreview = RouterApi.matchLocal(splitRules, target)
    }

    fun clearTest() {
        testResult = null
        testLocalPreview = null
    }

    // ------------------------------------------------------- high availability

    /**
     * Dual always-on Iran→USA leg (owner HA addendum): Tunnel A + Tunnel B,
     * both connected with independent keepalives; the panel mirrors the
     * backend's measured state — downtime shown is measured, never claimed.
     */
    fun refreshHa() = launch {
        api("GET", "/api/v1/ha/status")?.let {
            haStatus = HaApi.HaStatus.fromJson(it)
        }
    }

    /** Manual primary selection: traffic moves without a new connection setup. */
    fun setHaPrimary(tunnelId: String) = launch {
        val done = api("POST", "/api/v1/ha/primary", body = JSONObject().put("tunnel", tunnelId))
        if (done != null) {
            notify("Primary: tunnel $tunnelId")
            refreshHa()
        }
    }

    /** Mode switch — only to modes the backend declares available. */
    fun setHaMode(mode: String) = launch {
        if (haStatus?.availableModes?.contains(mode) != true) return@launch
        val done = api("POST", "/api/v1/ha/mode", body = JSONObject().put("mode", mode))
        if (done != null) {
            notify("HA mode: ${HaApi.modeLabel(mode)}")
            refreshHa()
        }
    }

    fun saveHaSettings(heartbeatIntervalS: Int, failoverThresholdMissed: Int, autoRecovery: Boolean) = launch {
        val done = api(
            "POST", "/api/v1/ha/settings",
            body = JSONObject()
                .put("heartbeat_interval_s", heartbeatIntervalS)
                .put("failover_threshold_missed", failoverThresholdMissed)
                .put("auto_recovery", autoRecovery),
        )
        if (done != null) {
            notify("HA settings saved")
            refreshHa()
        }
    }
}
