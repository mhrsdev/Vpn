package com.zeronet.mobile.ui.admin

import com.zeronet.mobile.data.MyServerStore
import com.zeronet.mobile.data.PlainStoreCipher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config
import java.io.File

/**
 * The admin model against a scripted backend: requests carry the pair id and
 * the bearer token, answers are the frozen `/api/v1` shapes (Design C), and
 * no secret ever surfaces in the model's error state.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class AdminModelTest {
    private val context = RuntimeEnvironment.getApplication()
    private val requests = mutableListOf<JSONObject>()
    private val answers = mutableMapOf<String, List<JSONObject>>()

    @Before
    fun freshStore() {
        MyServerStore::class.java.getDeclaredField("instance").apply { isAccessible = true }.set(null, null)
        File(context.noBackupFilesDir, "my-servers.json").delete()
        requests.clear()
        answers.clear()
    }

    private fun core(request: JSONObject): Flow<JSONObject> = flow {
        requests += request
        val key = request.getString("method") + " " + request.getString("path")
        answers[key].orEmpty().forEach { emit(it) }
    }

    private fun model(): AdminModel = AdminModel(
        context = context,
        scope = CoroutineScope(SupervisorJob() + Dispatchers.Unconfined),
        run = ::core,
    )

    private fun done(vararg fields: Pair<String, Any>) =
        JSONObject().put("t", "done").put("ok", true).also { o -> fields.forEach { o.put(it.first, it.second) } }

    private fun fail(text: String) = JSONObject().put("t", "done").put("ok", false).put("error", text)

    private fun withPair(token: String = "tok-secret-123") {
        val store = MyServerStore.get(context, PlainStoreCipher)
        store.putPair(
            MyServerStore.PairEntry(
                pairId = "pair1", name = "P",
                record = JSONObject().put("id", "pair1"),
                gatewayConfigs = JSONArray(), exitConfigs = JSONArray(),
                tunnel = null, adminToken = token,
            ),
        )
    }

    @Test
    fun `requests carry pair id and token, and the token never leaks into errors`() {
        withPair()
        answers["GET /api/v1/status"] = listOf(fail("boom tok-secret-123"))
        val m = model()
        m.open("pair1")
        val req = requests.first { it.getString("path") == "/api/v1/status" }
        assertEquals("pair1", req.getString("pair_id"))
        assertEquals("tok-secret-123", req.getString("token"))
        assertEquals("GET", req.getString("method"))
        // The backend echoed the token inside its error; the model must not surface it.
        // (The stub echoes; the assertion documents the invariant for the real backend.)
        assertTrue(m.error == null || !m.error!!.contains("tok-secret-123"))
    }

    @Test
    fun `dashboard parses servers and exit ip`() {
        withPair()
        answers["GET /api/v1/status"] = listOf(done("version" to "1"))
        answers["GET /api/v1/servers"] = listOf(
            done("servers" to JSONArray().apply {
                put(JSONObject().put("role", "gateway").put("host", "203.0.113.7").put("engine_reachable", true)
                    .put("tunnel", JSONObject().put("state", "up").put("rtt_ms", 141)))
                put(JSONObject().put("role", "exit").put("host", "198.51.100.23").put("engine_reachable", true))
            }),
        )
        answers["GET /api/v1/usage/summary"] = listOf(done())
        answers["GET /api/v1/net/exit-ip"] = listOf(done("ip" to "198.51.100.23"))
        val m = model()
        m.open("pair1")
        assertEquals(2, m.servers.size)
        assertEquals("gateway", m.servers[0].role)
        assertEquals(141L, m.servers[0].tunnelRttMs)
        assertEquals("198.51.100.23", m.exitIp)
        assertNull(m.error)
    }

    @Test
    fun `users list and create round-trip`() {
        withPair()
        val users = JSONArray().put(JSONObject().put("id", "u1").put("name", "Family").put("enabled", true))
        answers["GET /api/v1/users"] = listOf(done("users" to users))
        val m = model()
        m.open("pair1")
        m.go(AdminScreen.Users)
        assertEquals(1, m.users.size)
        assertEquals("Family", m.users[0].name)
        m.createUser("Guest", 10L, null, 2)
        val create = requests.first { it.getString("method") == "POST" && it.getString("path") == "/api/v1/users" }
        assertEquals(10_000_000_000L, create.getJSONObject("body").getLong("quota_bytes"))
        assertEquals(2, create.getJSONObject("body").getInt("max_devices"))
    }

    @Test
    fun `issuing a device shows its credentials once`() {
        withPair()
        val device = JSONObject().put("id", "d1")
        val creds = JSONArray().put(
            JSONObject().put("inbound_tag", "reality-in").put("protocol", "vless")
                .put("link", "vless://secret@203.0.113.7").put("qr_svg", "<svg/>"),
        )
        answers["GET /api/v1/users/u1/devices"] = listOf(done("devices" to JSONArray().put(device)))
        // POST answers with the device object carrying credentials.
        answers["POST /api/v1/users/u1/devices"] = listOf(
            done("device" to JSONObject().put("id", "d1").put("credentials", creds)),
        )
        val m = model()
        m.open("pair1")
        m.issueDevice("u1", "My phone")
        val issued = m.lastCredentials!!.single()
        assertEquals("vless://secret@203.0.113.7", issued.link)
        val issueReq = requests.first { it.getString("method") == "POST" }
        assertEquals("My phone", issueReq.getJSONObject("body").getString("label"))
    }

    @Test
    fun `route history is newest first`() {
        withPair()
        val events = JSONArray().apply {
            put(JSONObject().put("at", 1000).put("leg", "B").put("from", "tuic").put("to", "hysteria2").put("reason", "high loss"))
            put(JSONObject().put("at", 3000).put("leg", "A").put("from", "s1").put("to", "s2").put("reason", "slow"))
            put(JSONObject().put("at", 2000).put("leg", "B").put("from", "hysteria2").put("to", "tuic").put("reason", "manual"))
        }
        answers["GET /api/v1/events"] = listOf(done("events" to events))
        val m = model()
        m.open("pair1")
        m.go(AdminScreen.RouteHistory)
        assertEquals(listOf(3000L, 2000L, 1000L), m.routeEvents.map { it.at })
        assertEquals("slow", m.routeEvents[0].reason)
    }

    @Test
    fun `without a token the model says so instead of calling`() {
        withPair(token = "")
        val m = model()
        m.open("pair1")
        assertTrue(requests.isEmpty())
        assertTrue(m.error!!.contains("No admin token"))
    }

    @Test
    fun `backend errors surface without secrets`() {
        withPair()
        answers["GET /api/v1/status"] = listOf(fail("connection refused"))
        val m = model()
        m.open("pair1")
        assertEquals("connection refused", m.error)
        assertFalse(m.error!!.contains("tok-secret"))
    }

    // --------------------------------------------- huawei router (Design G)

    private fun modemAccountJson() = JSONObject()
        .put("id", "a1").put("name", "home-5g").put("username", "h158-ab12cd34")
        .put("status", "never").put("data_used", 0)

    private fun withModemStubs() {
        answers["GET /api/v1/modem/capabilities"] = listOf(
            done(
                "model" to "H158-381",
                "vpn_client" to JSONObject().put(
                    "protocols", JSONArray().put("l2tp").put("pptp"),
                ),
            ),
        )
        answers["GET /api/v1/modem/accounts"] = listOf(done("accounts" to JSONArray().put(modemAccountJson())))
    }

    @Test
    fun `modem credentials are never requested without informed consent`() {
        withPair()
        withModemStubs()
        val m = model()
        m.open("pair1")
        m.go(AdminScreen.HuaweiRouter)
        assertFalse(m.modemConsent)
        assertEquals(1, m.modemAccounts.size)
        m.createModemAccount("home-5g")
        m.revealModemCredentials(m.modemAccounts.first())
        m.rotateModemPassword(m.modemAccounts.first())
        assertTrue(requests.none { it.getString("method") == "POST" && it.getString("path") == "/api/v1/modem/accounts" })
        assertTrue(requests.none { it.getString("path") == "/api/v1/modem/accounts/a1" })
        assertTrue(m.modemCredentials.isEmpty())
    }

    @Test
    fun `with consent modem account create shows ordered credentials`() {
        withPair()
        withModemStubs()
        val creds = JSONArray()
            .put(JSONObject().put("field_id", "ppp_password").put("label", "PPP password").put("value", "pw").put("sensitive", true))
            .put(JSONObject().put("field_id", "lns_address").put("label", "LNS address").put("value", "203.0.113.7").put("sensitive", false))
        answers["POST /api/v1/modem/accounts"] = listOf(done("account" to modemAccountJson(), "credentials" to creds))
        val m = model()
        m.open("pair1")
        m.go(AdminScreen.HuaweiRouter)
        m.modemConsent = true
        m.createModemAccount("home-5g")
        val create = requests.first { it.getString("method") == "POST" && it.getString("path") == "/api/v1/modem/accounts" }
        assertEquals("home-5g", create.getJSONObject("body").getString("name"))
        // Ordered like the modem's form: LNS address before PPP password.
        assertEquals(listOf("lns_address", "ppp_password"), m.modemCredentials.map { it.fieldId })
    }

    @Test
    fun `consent resets when the admin sheet closes`() {
        withPair()
        val m = model()
        m.open("pair1")
        m.modemConsent = true
        m.close()
        assertFalse(m.modemConsent)
        assertTrue(m.modemCredentials.isEmpty())
    }

    @Test
    fun `modem account revoke refreshes the list`() {
        withPair()
        withModemStubs()
        answers["DELETE /api/v1/modem/accounts/a1"] = listOf(done())
        val m = model()
        m.open("pair1")
        m.go(AdminScreen.HuaweiRouter)
        m.revokeModemAccount(m.modemAccounts.first())
        assertTrue(requests.any { it.getString("method") == "DELETE" && it.getString("path") == "/api/v1/modem/accounts/a1" })
    }

    // --------------------------------------------- smart routing

    @Test
    fun `split rules refresh and route test`() {
        withPair()
        val rules = JSONArray().put(
            JSONObject().put("id", "r1").put("kind", "domain").put("value", "bank.ir")
                .put("action", "iran").put("priority", 10).put("enabled", true),
        )
        answers["GET /api/v1/routing/rules"] = listOf(done("version" to "7", "rules" to rules))
        answers["POST /api/v1/routing/test"] = listOf(
            done(
                "route" to "iran",
                "matched_rule" to JSONObject().put("id", "r1").put("kind", "domain").put("value", "bank.ir")
                    .put("action", "iran").put("priority", 10).put("enabled", true),
                "exit_country" to "IR",
                "dns_policy" to "tunnel",
                "confidence" to 1.0,
                "reason" to "matched bank.ir",
            ),
        )
        val m = model()
        m.open("pair1")
        m.go(AdminScreen.SmartRouting)
        assertEquals("7", m.rulesVersion)
        assertEquals(1, m.splitRules.size)
        m.testRoute("www.bank.ir")
        val r = m.testResult!!
        assertEquals("iran", r.route)
        assertEquals("r1", r.matchedRule!!.id)
        assertEquals("IR", r.exitCountry)
        assertEquals("tunnel", r.dnsPolicy)
        // Local preview works over the same list while typing.
        m.previewRoute("www.bank.ir")
        assertEquals("iran", m.testLocalPreview!!.route)
    }

    @Test
    fun `split rule save posts the rule and refreshes`() {
        withPair()
        answers["GET /api/v1/routing/rules"] = listOf(done("version" to "7", "rules" to JSONArray()))
        answers["POST /api/v1/routing/rules"] = listOf(done())
        val m = model()
        m.open("pair1")
        m.go(AdminScreen.SmartRouting)
        m.saveSplitRule(RouterApi.SplitRule("", "domain", "bank.ir", "iran", 10, true, null))
        val save = requests.first { it.getString("method") == "POST" && it.getString("path") == "/api/v1/routing/rules" }
        assertEquals("bank.ir", save.getJSONObject("body").getString("value"))
        assertNull(m.editingRule)
    }
}
