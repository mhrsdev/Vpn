package com.zeronet.mobile.ui.myserver

import com.zeronet.mobile.data.MyServerStore
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
 * The pair wizard's state machine against a scripted core: every request the
 * page makes is recorded and answered with the events the real job would
 * send (see Design A §6), so no network and no server are involved.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class DualServerModelTest {
    private val context = RuntimeEnvironment.getApplication()
    private val requests = mutableListOf<JSONObject>()
    private val answers = mutableMapOf<String, List<JSONObject>>()
    private val notices = mutableListOf<String>()

    @Before
    fun freshStore() {
        MyServerStore::class.java.getDeclaredField("instance").apply { isAccessible = true }.set(null, null)
        File(context.noBackupFilesDir, "my-servers.json").delete()
        requests.clear()
        answers.clear()
        notices.clear()
    }

    private fun model(): PairModel = PairModel(
        context = context,
        scope = CoroutineScope(SupervisorJob() + Dispatchers.Unconfined),
        run = ::core,
        importLink = { true },
        notify = { notices += it },
    )

    private fun core(request: JSONObject): Flow<JSONObject> = flow {
        requests += request
        answers[request.getString("op")].orEmpty().forEach { emit(it) }
    }

    private fun done(vararg fields: Pair<String, Any>) =
        JSONObject().put("t", "done").put("ok", true).also { o -> fields.forEach { o.put(it.first, it.second) } }

    private fun fail(text: String) = JSONObject().put("t", "done").put("ok", false).put("error", text)

    private fun step(name: String, server: String? = null) =
        JSONObject().put("t", "step").put("step", name).also { o -> server?.let { o.put("server", it) } }

    private fun pairRecord(id: String = "pair1") = JSONObject()
        .put("id", id).put("name", "P")
        .put("gateway", JSONObject().put("id", "g1").put("host", "203.0.113.7").put("services", JSONArray()))
        .put("exit", JSONObject().put("id", "e1").put("host", "198.51.100.23").put("services", JSONArray()))

    private fun fill(m: PairModel) {
        m.startAdd()
        m.form.pairName = "P"
        m.form.iran.address = "203.0.113.7"; m.form.iran.password = "hunter2"
        m.form.usa.address = "198.51.100.23"; m.form.usa.password = "hunter3"
    }

    private fun fingerprintsOk() {
        answers["fingerprint_pair"] = listOf(
            done(
                "gateway" to JSONObject().put("fingerprint", "SHA256:aaa").put("algorithm", "ssh-ed25519"),
                "exit" to JSONObject().put("fingerprint", "SHA256:bbb").put("algorithm", "ssh-ed25519"),
            ),
        )
    }

    @Test
    fun `a form with a missing field says which one and sends nothing`() {
        val m = model()
        m.startAdd()
        m.form.iran.address = "203.0.113.7"; m.form.iran.password = "x"
        m.submitPair()
        assertEquals(context.getString(com.zeronet.mobile.R.string.ms_err_address_role, context.getString(com.zeronet.mobile.R.string.pair_usa)), m.form.error)
        assertTrue(requests.isEmpty())
    }

    @Test
    fun `trust goes per server, iran first`() {
        val m = model()
        fill(m)
        fingerprintsOk()
        m.submitPair()
        val first = m.screen as MsScreen.PairIdentity
        assertEquals(MsScreen.PairRole.Gateway, first.role)
        assertEquals("SHA256:aaa", first.fingerprint)
        m.trustPairIdentity()
        val second = m.screen as MsScreen.PairIdentity
        assertEquals(MsScreen.PairRole.Exit, second.role)
        assertEquals("SHA256:bbb", second.fingerprint)
        // One fingerprint_pair request, carrying both hosts and no secret.
        assertEquals(1, requests.count { it.getString("op") == "fingerprint_pair" })
        assertFalse(requests.single().toString().contains("hunter"))
    }

    @Test
    fun `install streams phases in order`() {
        val m = model()
        fill(m)
        fingerprintsOk()
        // No `done` yet: the progress screen stays up with every phase seen.
        answers["install_pair"] = listOf(
            step("install", "Gateway"),
            step("install", "Exit"),
            step("tunnel_up"),
            step("verify_e2e"),
        )
        m.submitPair()
        m.trustPairIdentity()
        m.trustPairIdentity()
        val progress = m.screen as MsScreen.PairProgress
        assertEquals(MsScreen.PairPhase.Verifying, progress.phase)
        assertEquals(4, progress.steps.size)
        assertNull(progress.failed)
    }

    @Test
    fun `a successful install clears both passwords and saves the pair`() {
        val m = model()
        fill(m)
        fingerprintsOk()
        answers["install_pair"] = listOf(
            step("install", "Gateway"),
            done("record" to pairRecord(), "notes" to JSONArray(), "configs" to JSONArray(), "admin_token" to "tok123"),
        )
        m.submitPair()
        m.trustPairIdentity()
        m.trustPairIdentity()
        // Both passwords left the forms the moment the request was built.
        assertTrue(m.form.iran.password.isEmpty())
        assertTrue(m.form.usa.password.isEmpty())
        val result = m.screen as MsScreen.PairResult
        assertEquals("pair1", result.pairId)
        // The pair is saved with the admin token, encrypted at rest.
        val saved = MyServerStore.get(context).pairs().single()
        assertEquals("pair1", saved.pairId)
        assertEquals("tok123", saved.adminToken)
        // The install request carries both servers, protocols and keep_access.
        val req = requests.single { it.getString("op") == "install_pair" }
        assertEquals("203.0.113.7", req.getJSONObject("gateway").getString("host"))
        assertEquals("198.51.100.23", req.getJSONObject("exit").getString("host"))
        assertTrue(req.getBoolean("keep_access"))
        assertTrue(req.getJSONObject("protocols").getJSONArray("gateway").length() > 0)
    }

    @Test
    fun `phase mapping never moves backwards`() {
        val m = model()
        val cur = MsScreen.PairPhase.UsaInstall
        assertEquals(MsScreen.PairPhase.UsaInstall, m.phaseFor("install", "Gateway", cur))
        assertEquals(MsScreen.PairPhase.Linking, m.phaseFor("tunnel_up", null, cur))
        assertEquals(MsScreen.PairPhase.Verifying, m.phaseFor("verify_e2e", null, MsScreen.PairPhase.Linking))
    }

    @Test
    fun `a failed install shows which error and offers rollback`() {
        val m = model()
        fill(m)
        fingerprintsOk()
        answers["install_pair"] = listOf(step("install", "Gateway"), fail("tunnel refused"))
        m.submitPair()
        m.trustPairIdentity()
        m.trustPairIdentity()
        val progress = m.screen as MsScreen.PairProgress
        assertEquals("tunnel refused", progress.failed)
        // Rollback that needs a password says so honestly.
        answers["rollback_pair"] = listOf(fail("need_password"))
        val record = pairRecord()
        val entry = MyServerStore.PairEntry("pair1", "P", record, JSONArray(), JSONArray(), null, null)
        MyServerStore.get(context).putPair(entry)
        m.pairs.add(entry)
        m.rollbackPair("pair1")
        assertEquals(context.getString(com.zeronet.mobile.R.string.pair_rollback_needs_password), m.notice)
    }

    @Test
    fun `remove_pair drops the saved pair`() {
        val m = model()
        val record = pairRecord()
        val entry = MyServerStore.PairEntry("pair1", "P", record, JSONArray(), JSONArray(), null, null)
        MyServerStore.get(context).putPair(entry)
        m.pairs.add(entry)
        answers["remove_pair"] = listOf(done())
        m.removePair("pair1")
        assertTrue(MyServerStore.get(context).pairs().isEmpty())
        assertTrue(m.screen is MsScreen.PairList)
    }

    @Test
    fun `closing the page keeps a running install alive`() {
        val m = model()
        fill(m)
        fingerprintsOk()
        answers["install_pair"] = emptyList()
        m.submitPair()
        m.trustPairIdentity()
        m.trustPairIdentity()
        assertTrue(m.screen is MsScreen.PairProgress)
        m.close()
        assertFalse(m.open)
        // The progress state survives the close: reopening shows it, because
        // close() never cancels a running install (only a failed one).
        assertTrue(m.screen is MsScreen.PairProgress)
        m.show()
        assertTrue(m.screen is MsScreen.PairProgress)
    }
}
