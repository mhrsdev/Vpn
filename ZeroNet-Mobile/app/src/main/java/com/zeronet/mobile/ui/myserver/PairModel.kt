package com.zeronet.mobile.ui.myserver

import android.content.Context
import androidx.compose.runtime.Stable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import com.zeronet.mobile.R
import com.zeronet.mobile.data.MyServerStore
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject

/**
 * The dual-server form: one [ServerForm] per role. Passwords and keys live
 * here only until the `install_pair` request is built, then are cleared —
 * the same credential invariant as [ServerForm] in the single-server flow.
 */
@Stable
class PairForm {
    val iran = ServerForm()
    val usa = ServerForm()
    var pairName by mutableStateOf("")
    var error by mutableStateOf<String?>(null)
}

/** The tunnel's health, as `tunnel_status` reports it (Design A §6). */
data class TunnelStatus(
    val up: Boolean,
    val lastHandshakeSecsAgo: Long?,
    val gatewayRx: Long,
    val gatewayTx: Long,
    val error: String?,
    /** `up`, `down`, or `idle` (nothing has used the tunnel yet, so it is not known). */
    val state: String = if (up) "up" else "down",
)

/** Live figures for both ends of a pair. */
data class PairUsageView(val gateway: UsageView?, val exit: UsageView?)

/**
 * State and actions of the Iran/USA pair wizard.
 *
 * Drives the provisioning agent's pair ops (`fingerprint_pair`,
 * `install_pair`, `link_servers`, `tunnel_status`, `usage_pair`,
 * `remove_pair`, `rollback_pair`, `configs_pair` — Design A §6) through the
 * same injected [run] plumbing as [MyServerModel], so tests script the core
 * the same way. No new JNI: everything rides the existing `serverJob`
 * op dispatcher.
 *
 * Order: PairForm → PairIdentity(Gateway) → PairIdentity(Exit) →
 * PairProgress(IranInstall → UsaInstall → Linking → Verifying) → PairResult.
 * Closing the page never cancels a running install (same rationale as the
 * single-server flow: a half-installed pair is worse than a slow one).
 */
@Stable
class PairModel(
    private val context: Context,
    private val scope: CoroutineScope,
    /** Run one request in the core and stream its events (see [EngineClient.serverCall]). */
    private val run: (JSONObject) -> Flow<JSONObject>,
    /** Add a share link to the app's own server list (so the person can connect to it). */
    private val importLink: suspend (String) -> Boolean,
    private val notify: (String) -> Unit,
    /** Put text on the clipboard; `sensitive` hides it from clipboard previews (links hold keys). */
    val copy: (text: String, sensitive: Boolean) -> Unit = { _, _ -> },
    /** Start a system screen, such as the share sheet. */
    val startIntent: (android.content.Intent) -> Unit = {},
) {
    private val store = MyServerStore.get(context)

    var open by mutableStateOf(false)
    var screen by mutableStateOf<MsScreen>(MsScreen.PairForm)
        private set
    val pairs = mutableStateListOf<MyServerStore.PairEntry>()
    val form = PairForm()
    var shown by mutableStateOf(0)
    val usage = mutableStateMapOf<String, PairUsageView>()
    val tunnel = mutableStateMapOf<String, TunnelStatus>()
    val tunnelError = mutableStateMapOf<String, String>()
    var notice by mutableStateOf<String?>(null)

    private var job: Job? = null
    private var usageJob: Job? = null
    private var pendingGwFp = ""
    private var pendingGwAlgo = ""
    private var pendingExitFp = ""
    private var pendingExitAlgo = ""

    init {
        scope.launch {
            val saved = withContext(Dispatchers.IO) { store.pairs() }
            pairs.clear()
            pairs.addAll(saved)
        }
    }

    fun pair(id: String): MyServerStore.PairEntry? = pairs.firstOrNull { it.pairId == id }

    // ------------------------------------------------------------ navigation

    fun show() {
        open = true
        val running = (screen as? MsScreen.PairProgress)?.takeIf { it.failed == null }
        if (running == null) screen = MsScreen.PairList
    }

    fun close() {
        forgetSecrets()
        if ((screen as? MsScreen.PairProgress)?.failed != null || screen !is MsScreen.PairProgress) job?.cancel()
        usageJob?.cancel()
        open = false
    }

    fun back() {
        when (val s = screen) {
            MsScreen.PairList -> close()
            MsScreen.PairForm -> screen = MsScreen.PairList
            is MsScreen.PairIdentity -> screen =
                if (s.role == MsScreen.PairRole.Exit) MsScreen.PairIdentity(MsScreen.PairRole.Gateway, pendingGwFp, pendingGwAlgo)
                else MsScreen.PairForm
            MsScreen.Busy -> { job?.cancel(); screen = MsScreen.PairForm }
            is MsScreen.PairProgress -> if (s.failed != null) { restoreSecrets(); screen = MsScreen.PairForm } else close()
            is MsScreen.PairResult -> openPair(s.pairId)
            is MsScreen.PairServer -> { usageJob?.cancel(); screen = MsScreen.PairList }
            is MsScreen.ConfirmRemovePair -> screen = MsScreen.PairServer(s.pairId)
            else -> close()
        }
    }

    fun startAdd() {
        forgetSecrets()
        form.iran.password = ""; form.iran.keyText = ""; form.iran.passphrase = ""
        form.usa.password = ""; form.usa.keyText = ""; form.usa.passphrase = ""
        form.error = null
        if (form.pairName.isBlank()) form.pairName = context.getString(R.string.pair_default_name)
        screen = MsScreen.PairForm
    }

    fun openPair(pairId: String) {
        notice = null
        shown = 0
        screen = MsScreen.PairServer(pairId)
    }

    // ---------------------------------------------------------------- the form

    /** Check both forms and fetch both fingerprints in parallel; no secret is sent. */
    fun submitPair() {
        val problem = validate()
        if (problem != null) {
            form.error = problem
            return
        }
        form.error = null
        screen = MsScreen.Busy
        job?.cancel()
        job = scope.launch {
            val done = call(JSONObject()
                .put("op", "fingerprint_pair")
                .put("gateway", JSONObject().put("host", form.iran.address.trim()).put("port", form.iran.port.trim().toInt()))
                .put("exit", JSONObject().put("host", form.usa.address.trim()).put("port", form.usa.port.trim().toInt())))
            if (screen != MsScreen.Busy) return@launch
            if (done.optBoolean("ok")) {
                val gw = done.getJSONObject("gateway")
                val ex = done.getJSONObject("exit")
                pendingGwFp = gw.optString("fingerprint"); pendingGwAlgo = gw.optString("algorithm")
                pendingExitFp = ex.optString("fingerprint"); pendingExitAlgo = ex.optString("algorithm")
                screen = MsScreen.PairIdentity(MsScreen.PairRole.Gateway, pendingGwFp, pendingGwAlgo)
            } else {
                form.error = done.optString("error")
                screen = MsScreen.PairList
            }
        }
    }

    private fun validate(): String? {
        validateForm(form.iran, R.string.pair_iran)?.let { return it }
        validateForm(form.usa, R.string.pair_usa)?.let { return it }
        return null
    }

    private fun validateForm(f: ServerForm, roleName: Int): String? {
        val role = context.getString(roleName)
        val address = f.address.trim()
        if (address.isEmpty()) return context.getString(R.string.ms_err_address_role, role)
        if (address.any { it.isWhitespace() } || address.contains("://")) return context.getString(R.string.ms_err_address_shape)
        if (f.port.trim().toIntOrNull()?.let { it in 1..65535 } != true) return context.getString(R.string.ms_err_port)
        if (f.user.isBlank()) return context.getString(R.string.ms_err_user)
        if (f.useKey) {
            if (f.keyText.isBlank()) return context.getString(R.string.ms_err_key)
            if (!looksLikePrivateKey(f.keyText)) return context.getString(R.string.ms_err_key_shape)
        } else if (f.password.isEmpty()) {
            return context.getString(R.string.ms_err_password)
        }
        if (!f.reality && !f.xhttp && !f.masterdns) return context.getString(R.string.ms_err_choose_role, role)
        if (f.masterdns && f.domain.isBlank()) return context.getString(R.string.ms_err_domain)
        return null
    }

    /** The person trusted this end's fingerprint; the other end comes next, then the install. */
    fun trustPairIdentity() {
        val identity = screen as? MsScreen.PairIdentity ?: return
        if (identity.role == MsScreen.PairRole.Gateway) {
            screen = MsScreen.PairIdentity(MsScreen.PairRole.Exit, pendingExitFp, pendingExitAlgo)
        } else {
            installPair()
        }
    }

    /**
     * Credentials of a pair install that is running or just failed, kept in
     * memory only so "Back" after a failure does not make the user retype
     * them. Never persisted; dropped on success, on close and on a new form.
     */
    private var retained: List<Triple<String, String, String>>? = null

    private fun retainSecrets() {
        retained = listOf(form.iran, form.usa).map { Triple(it.password, it.keyText, it.passphrase) }
    }

    private fun restoreSecrets() {
        val r = retained ?: return
        listOf(form.iran, form.usa).zip(r).forEach { (f, t) ->
            f.password = t.first; f.keyText = t.second; f.passphrase = t.third
        }
    }

    private fun forgetSecrets() { retained = null }

    /** Start the pair install. Both passwords leave their forms here. */
    fun installPair() {
        val request = JSONObject()
            .put("op", "install_pair")
            .put("name", form.pairName.trim().ifEmpty { context.getString(R.string.pair_default_name) })
            .put("gateway", serverJson(form.iran, pendingGwFp, pendingGwAlgo))
            .put("exit", serverJson(form.usa, pendingExitFp, pendingExitAlgo))
            .put("protocols", JSONObject()
                .put("gateway", protocolList(form.iran))
                .put("exit", protocolList(form.usa))
                .put("exit_egress", "direct"))
            .put("keep_access", true)
        ServerProgram.dir(context)?.let { request.put("local_binary_dir", it) }
        if (form.iran.masterdns) request.put("masterdns_domain", form.iran.domain.trim())
        retainSecrets()
        form.iran.password = ""; form.iran.keyText = ""; form.iran.passphrase = ""
        form.usa.password = ""; form.usa.keyText = ""; form.usa.passphrase = ""
        var progress = MsScreen.PairProgress(emptyList(), "", null, MsScreen.PairPhase.IranInstall)
        screen = progress
        job?.cancel()
        job = scope.launch {
            try {
                run(request).collect { e ->
                    when (e.optString("t")) {
                        "step" -> {
                            val server = e.optString("server").takeIf { it.isNotEmpty() && it != "null" }
                            val nextPhase = phaseFor(e.optString("step"), server, progress.phase)
                            val steps = progress.steps.map { it.copy(done = true) } +
                                StepView(e.optString("step"), e.optString("preset").takeIf { it.isNotEmpty() && it != "null" }, false)
                            progress = progress.copy(steps = steps, phase = nextPhase)
                            screen = progress
                        }
                        "detail" -> {
                            progress = progress.copy(detail = e.optString("text"))
                            screen = progress
                        }
                        "done" -> if (e.optBoolean("ok")) finishPairInstall(e) else {
                            screen = progress.copy(failed = e.optString("error"))
                        }
                    }
                }
            } catch (c: CancellationException) {
                throw c
            }
        }
    }

    private fun serverJson(f: ServerForm, fingerprint: String, algorithm: String): JSONObject {
        val o = JSONObject()
            .put("host", f.address.trim())
            .put("port", f.port.trim().toInt())
            .put("user", f.user.trim())
            .put("trust", JSONObject().put("fingerprint", fingerprint).put("algorithm", algorithm))
        if (f.useKey) {
            o.put("private_key", f.keyText.trim())
            if (f.passphrase.isNotEmpty()) o.put("key_passphrase", f.passphrase)
        } else {
            o.put("password", f.password)
        }
        return o
    }

    /** The installable protocol keys for one end (Design A §4.2 row keys). */
    private fun protocolList(f: ServerForm): JSONArray = JSONArray().apply {
        if (f.reality) put("reality")
        if (f.xhttp) put("xhttp")
        if (f.masterdns) put("masterdns")
    }

    /**
     * Map a step event to the wizard phase. The core tags per-server steps
     * with `server` (Gateway/Exit, Design A §6); tunnel steps carry no server
     * tag and verification steps name themselves.
     */
    internal fun phaseFor(step: String, server: String?, current: MsScreen.PairPhase): MsScreen.PairPhase {
        val next = when {
            step.contains("verify", ignoreCase = true) || step.contains("e2e", ignoreCase = true) -> MsScreen.PairPhase.Verifying
            server.equals("Gateway", ignoreCase = true) -> MsScreen.PairPhase.IranInstall
            server.equals("Exit", ignoreCase = true) -> MsScreen.PairPhase.UsaInstall
            step.contains("tunnel", ignoreCase = true) || step.contains("link", ignoreCase = true) -> MsScreen.PairPhase.Linking
            else -> current
        }
        // Phases never move backwards (out-of-order step events stay readable).
        return if (next.ordinal >= current.ordinal) next else current
    }

    private suspend fun finishPairInstall(done: JSONObject) {
        forgetSecrets()
        val record = done.getJSONObject("record")
        // The admin bearer token arrives once, inside the done event (Design C):
        // never logged, encrypted at rest like the SSH keys.
        val adminToken = done.optString("admin_token").takeIf { it.isNotEmpty() }
            ?: record.optString("admin_token").takeIf { it.isNotEmpty() }
        val configs = done.optJSONArray("configs") ?: JSONArray()
        val pairId = record.optString("id").takeIf { it.isNotEmpty() }
            ?: MyServerStore.pairIdOf(record.optJSONObject("gateway")?.optString("id").orEmpty(), record.optJSONObject("exit")?.optString("id").orEmpty())
        val entry = MyServerStore.PairEntry(
            pairId = pairId,
            name = record.optString("name"),
            record = record,
            gatewayConfigs = configs,
            exitConfigs = JSONArray(),
            tunnel = done.optJSONObject("tunnel") ?: record.optJSONObject("tunnel"),
            adminToken = adminToken,
        )
        withContext(Dispatchers.IO) { store.putPair(entry) }
        pairs.removeAll { it.pairId == pairId }
        pairs.add(entry)
        val notes = done.optJSONArray("notes").objects().mapNotNull { it.optString("text").takeIf { s -> s.isNotEmpty() } }
        shown = 0
        screen = MsScreen.PairResult(pairId, notes)
    }

    // ------------------------------------------------------------- one pair

    /** Read both ends' figures now, then every few seconds while the pair page stays open. */
    fun watchPair(pairId: String) {
        usageJob?.cancel()
        usageJob = scope.launch {
            var tunnelTicks = 0
            while (screen == MsScreen.PairServer(pairId)) {
                refreshPairUsage(pairId)
                if (tunnelTicks++ % 2 == 0) refreshTunnel(pairId)
                kotlinx.coroutines.delay(POLL_MS)
            }
        }
    }

    fun stopWatching() {
        usageJob?.cancel()
    }

    suspend fun refreshPairUsage(pairId: String) {
        val p = pair(pairId) ?: return
        val done = call(JSONObject().put("op", "usage_pair").put("record", p.record))
        if (done.optBoolean("ok")) {
            usage[pairId] = PairUsageView(
                gateway = done.optJSONObject("gateway")?.let { usageView(it) },
                exit = done.optJSONObject("exit")?.let { usageView(it) },
            )
        }
    }

    private fun usageView(u: JSONObject) = UsageView(
        u.optLong("window_secs"),
        u.optJSONArray("inbounds").objects().map {
            InboundUsage(
                it.optString("tag"), it.optLong("sessions"), it.optLong("devices_now"),
                it.optLong("devices_recent"), it.optLong("uplink"), it.optLong("downlink"),
            )
        },
        System.currentTimeMillis(),
    )

    suspend fun refreshTunnel(pairId: String) {
        val p = pair(pairId) ?: return
        val done = call(JSONObject().put("op", "tunnel_status").put("record", p.record))
        if (done.optBoolean("ok")) {
            tunnelError.remove(pairId)
            tunnel[pairId] = TunnelStatus(
                up = done.optBoolean("up"),
                lastHandshakeSecsAgo = done.optLong("last_handshake_secs_ago").takeIf { done.has("last_handshake_secs_ago") },
                gatewayRx = done.optLong("gateway_rx"),
                gatewayTx = done.optLong("gateway_tx"),
                error = null,
                state = done.optString("state").takeIf { it.isNotEmpty() } ?: if (done.optBoolean("up")) "up" else "down",
            )
        } else if (done.optString("error") != "cancelled") {
            tunnel[pairId] = TunnelStatus(false, null, 0, 0, done.optString("error"))
        }
    }

    /** Re-run the tunnel phase (link down, or after changing tunnel settings). */
    fun relink(pairId: String) {
        val p = pair(pairId) ?: return
        notice = context.getString(R.string.pair_relinking)
        scope.launch {
            val done = call(JSONObject().put("op", "link_servers").put("record", p.record))
            if (done.optBoolean("ok")) {
                val t = done.optJSONObject("tunnel")
                val updated = p.copy(tunnel = t ?: p.tunnel)
                withContext(Dispatchers.IO) { store.putPair(updated) }
                pairs.replaceAll { if (it.pairId == pairId) updated else it }
                refreshTunnel(pairId)
                notice = context.getString(R.string.pair_relinked)
            } else {
                notice = done.optString("error")
            }
        }
    }

    /** The gateway's client configs (what client apps point at). */
    fun configs(pairId: String): List<ConfigView> = pair(pairId)?.gatewayConfigs.objects().map { c ->
        ConfigView(
            service = c.optString("service"),
            user = c.optString("user"),
            link = c.optString("link").takeIf { it.isNotEmpty() && it != "null" },
            files = c.optJSONArray("files").objects().map { it.optString("name") to it.optString("text") },
        )
    }

    /** Add the pair's gateway link to the app's own list, so the person can connect to it. */
    fun useInApp(pairId: String) {
        val all = configs(pairId)
        val link = all.getOrNull(shown)?.link ?: all.firstNotNullOfOrNull { it.link } ?: return
        scope.launch {
            notify(context.getString(if (importLink(link)) R.string.ms_used_in_app else R.string.ms_use_failed))
        }
    }

    fun askRemovePair(pairId: String) {
        screen = MsScreen.ConfirmRemovePair(pairId)
    }

    fun removePair(pairId: String) {
        val p = pair(pairId) ?: return
        usageJob?.cancel()
        screen = MsScreen.Busy
        job?.cancel()
        job = scope.launch {
            val done = call(JSONObject().put("op", "remove_pair").put("record", p.record))
            if (done.optBoolean("ok")) {
                withContext(Dispatchers.IO) { store.removePair(pairId) }
                pairs.removeAll { it.pairId == pairId }
                usage.remove(pairId); tunnel.remove(pairId)
                notice = context.getString(R.string.pair_removed)
                screen = MsScreen.PairList
            } else {
                notice = done.optString("error")
                screen = MsScreen.PairServer(pairId)
            }
        }
    }

    /** Tear down a half-installed pair after the app died mid-install. */
    fun rollbackPair(pairId: String) {
        val p = pair(pairId) ?: return
        notice = context.getString(R.string.pair_rolling_back)
        scope.launch {
            val done = call(JSONObject().put("op", "rollback_pair").put("record", p.record))
            when {
                done.optBoolean("ok") -> {
                    withContext(Dispatchers.IO) { store.removePair(pairId) }
                    pairs.removeAll { it.pairId == pairId }
                    notice = context.getString(R.string.pair_rolled_back)
                    screen = MsScreen.PairList
                }
                done.optString("error") == "need_password" ->
                    notice = context.getString(R.string.pair_rollback_needs_password)
                else -> notice = done.optString("error")
            }
        }
    }

    /** Drop the saved record without touching the servers (unreachable or already gone). */
    fun forgetPair(pairId: String) {
        scope.launch {
            withContext(Dispatchers.IO) { store.removePair(pairId) }
            pairs.removeAll { it.pairId == pairId }
            usage.remove(pairId); tunnel.remove(pairId)
            screen = MsScreen.PairList
        }
    }

    // ------------------------------------------------------------------ plumbing

    /** Run one request and return its `done` event. */
    private suspend fun call(request: JSONObject): JSONObject {
        var last = JSONObject().put("t", "done").put("ok", false).put("error", "cancelled")
        run(request).collect { e -> if (e.optString("t") == "done") last = e }
        return last
    }

    companion object {
        private const val POLL_MS = 5_000L
    }
}

private fun JSONArray?.objects(): List<JSONObject> =
    if (this == null) emptyList() else List(length()) { getJSONObject(it) }
