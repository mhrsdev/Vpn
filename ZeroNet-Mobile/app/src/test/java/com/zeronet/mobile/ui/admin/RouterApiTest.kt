package com.zeronet.mobile.ui.admin

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4

/**
 * Vocabulary and matching gates for the two new admin sections (LEAD DELTA):
 * the honest modem-protocol security table (Design G) and the smart
 * split-routing rule matcher. Pure functions — no backend, no Android.
 */
@RunWith(JUnit4::class)
class RouterApiTest {

    private fun rule(
        id: String,
        kind: String,
        value: String,
        action: String,
        priority: Int = 10,
        enabled: Boolean = true,
    ) = RouterApi.SplitRule(id, kind, value, action, priority, enabled, null)

    // --------------------------------------------- modem security grades

    @Test fun `pptp is refused and never offered`() {
        val s = RouterApi.protocolSecurity("pptp")
        assertEquals(RouterApi.SecurityGrade.REFUSED, s.grade)
        assertFalse(s.offerable)
    }

    @Test fun `plain l2tp is weak and offerable with consent`() {
        val s = RouterApi.protocolSecurity("l2tp")
        assertEquals(RouterApi.SecurityGrade.WEAK, s.grade)
        assertTrue(s.offerable)
        // The wording must admit the weakness — never imply modern-VPN-grade.
        assertTrue(s.detail.contains("determined", ignoreCase = true))
    }

    @Test fun `wireguard on the modem is not available, never invented`() {
        val s = RouterApi.protocolSecurity("wireguard")
        assertEquals(RouterApi.SecurityGrade.NOT_AVAILABLE, s.grade)
        assertFalse(s.offerable)
    }

    @Test fun `unknown protocol is never labeled secure`() {
        val s = RouterApi.protocolSecurity("sstp")
        assertTrue(s.grade != RouterApi.SecurityGrade.OK)
        assertFalse(s.offerable)
    }

    @Test fun `no protocol is ever labeled OK in the modem table`() {
        listOf("pptp", "l2tp", "l2tp-ipsec", "ipsec", "openvpn", "wireguard", "ikev2").forEach { p ->
            val s = RouterApi.protocolSecurity(p)
            // The only honest modem outcomes: refused, weak-with-consent, or not available.
            assertTrue(
                "$p must not be labeled OK",
                s.grade == RouterApi.SecurityGrade.REFUSED ||
                    s.grade == RouterApi.SecurityGrade.WEAK ||
                    s.grade == RouterApi.SecurityGrade.NOT_AVAILABLE,
            )
        }
    }

    // --------------------------------------------- credential ordering

    @Test fun `credentials follow the modem form order`() {
        val creds = listOf(
            RouterApi.ModemCredential("ppp_password", "PPP password", "pw", true),
            RouterApi.ModemCredential("lns_address", "LNS address", "gw", false),
            RouterApi.ModemCredential("connection_type", "Connection type", "L2TP VPN client", false),
        )
        val ordered = RouterApi.orderCredentials(creds).map { it.fieldId }
        assertEquals(listOf("connection_type", "lns_address", "ppp_password"), ordered)
    }

    @Test fun `unknown field ids trail instead of being dropped`() {
        val creds = listOf(
            RouterApi.ModemCredential("future_field", "Future", "x", false),
            RouterApi.ModemCredential("lns_address", "LNS address", "gw", false),
        )
        val ordered = RouterApi.orderCredentials(creds).map { it.fieldId }
        assertEquals(listOf("lns_address", "future_field"), ordered)
    }

    // --------------------------------------------- modem account parsing

    @Test fun `modem accounts parse with defaults`() {
        val arr = JSONArray().put(
            JSONObject()
                .put("id", "a1")
                .put("name", "home-5g")
                .put("username", "h158-ab12cd34")
                .put("status", "connected")
                .put("data_used", 1500),
        )
        val acc = RouterApi.parseModemAccounts(arr).single()
        assertEquals("a1", acc.id)
        assertEquals("connected", acc.status)
        assertEquals(1500L, acc.dataUsed)
        assertNull(acc.lastSeen)
    }

    @Test fun `formatBytes stays readable`() {
        assertEquals("0 B", RouterApi.formatBytes(0))
        assertEquals("999 B", RouterApi.formatBytes(999))
        assertEquals("1.5 KB", RouterApi.formatBytes(1536))
        assertEquals("2.0 MB", RouterApi.formatBytes(2 * 1024 * 1024))
    }

    // --------------------------------------------- split-rule matching

    @Test fun `exact and subdomain domain matches`() {
        val rules = listOf(rule("1", "domain", "bank.ir", "iran"))
        assertEquals("iran", RouterApi.matchLocal(rules, "bank.ir")!!.route)
        assertEquals("iran", RouterApi.matchLocal(rules, "www.bank.ir")!!.route)
        assertNull(RouterApi.matchLocal(rules, "notbank.ir"))
        assertNull(RouterApi.matchLocal(rules, "bank.ir.evil.com"))
    }

    @Test fun `cidr matches inside the range only`() {
        val rules = listOf(rule("1", "cidr", "185.10.10.0/24", "iran"))
        assertEquals("iran", RouterApi.matchLocal(rules, "185.10.10.5")!!.route)
        assertNull(RouterApi.matchLocal(rules, "185.10.11.5"))
        assertNull(RouterApi.matchLocal(rules, "not-an-ip"))
    }

    @Test fun `unparsable cidr never matches (fail-closed)`() {
        val rules = listOf(rule("1", "cidr", "bogus", "iran"))
        assertNull(RouterApi.matchLocal(rules, "1.2.3.4"))
    }

    @Test fun `disabled rules are skipped`() {
        val rules = listOf(rule("1", "domain", "bank.ir", "iran", enabled = false))
        assertNull(RouterApi.matchLocal(rules, "bank.ir"))
    }

    @Test fun `priority decides between overlapping rules`() {
        val rules = listOf(
            rule("lo", "domain", "ir", "usa", priority = 20),
            rule("hi", "domain", "bank.ir", "iran", priority = 5),
        )
        val m = RouterApi.matchLocal(rules, "bank.ir")!!
        assertEquals("iran", m.route)
        assertEquals("hi", m.matchedRule!!.id)
    }

    @Test fun `geoip and unknown targets need the backend`() {
        val rules = listOf(rule("1", "geoip", "IR", "iran"))
        assertNull(RouterApi.matchLocal(rules, "1.2.3.4"))
        assertNull(RouterApi.matchLocal(emptyList(), "example.com"))
        assertNull(RouterApi.matchLocal(emptyList(), ""))
    }

    @Test fun `matched preview carries exit country and confidence`() {
        val rules = listOf(rule("1", "domain", "bank.ir", "iran"))
        val m = RouterApi.matchLocal(rules, "www.bank.ir")!!
        assertEquals("IR", m.exitCountry)
        assertTrue(m.confidence in 0.0..1.0)
    }

    @Test fun `rules parse sorted by priority`() {
        val arr = JSONArray()
            .put(rule("b", "domain", "x", "usa", 20).toJson())
            .put(rule("a", "domain", "y", "iran", 5).toJson())
        val parsed = RouterApi.parseSplitRules(arr)
        assertEquals(listOf("a", "b"), parsed.map { it.id })
    }

    @Test fun `route test result parses`() {
        val o = JSONObject()
            .put("route", "usa")
            .put("matched_rule", JSONObject().put("id", "r1").put("kind", "domain").put("value", "x.com").put("action", "usa").put("priority", 10).put("enabled", true))
            .put("exit_country", "US")
            .put("dns_policy", "tunnel")
            .put("confidence", 0.9)
            .put("reason", "matched")
        val r = RouterApi.RouteTestResult.fromJson(o)
        assertEquals("usa", r.route)
        assertEquals("r1", r.matchedRule!!.id)
        assertEquals("US", r.exitCountry)
        assertEquals("tunnel", r.dnsPolicy)
        assertEquals(0.9, r.confidence, 1e-9)
    }
}
