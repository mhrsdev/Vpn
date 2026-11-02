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
 * Vocabulary and formatting gates for the Inter-Server High Availability
 * section (owner HA addendum, binding). Pure functions — no backend, no Android.
 *
 * The honesty invariants under test: downtime is formatted from measured
 * values (never invented), unknown modes are shown as-is (never silently
 * mapped), and a down tunnel is never a primary candidate (fail-closed).
 */
@RunWith(JUnit4::class)
class HaApiTest {

    private fun statusJson() = JSONObject()
        .put("tunnels", JSONArray()
            .put(JSONObject()
                .put("id", "A").put("protocol", "wireguard").put("transport_family", "udp")
                .put("state", "up").put("rtt_ms", 141).put("loss_pct", 0.2)
                .put("jitter_ms", 9).put("keepalive_ok", true)
                .put("last_heartbeat_at", 1_000_000L)
                .put("bytes_up", 2048).put("bytes_down", 5_242_880))
            .put(JSONObject()
                .put("id", "B").put("protocol", "tuic").put("transport_family", "udp")
                .put("state", "standby").put("keepalive_ok", true)
                .put("last_heartbeat_at", 999_000L)))
        .put("primary", "A")
        .put("mode", "hot_standby")
        .put("available_modes", JSONArray().put("hot_standby"))
        .put("auto_recovery", true)
        .put("heartbeat_interval_s", 3)
        .put("failover_threshold_missed", 3)
        .put("last_failover_at", 900_000L)
        .put("failover_count", 2)
        .put("total_downtime_s", 75.0)
        .put("recent_failovers", JSONArray().put(
            JSONObject().put("at", 900_000L).put("from", "A").put("to", "B")
                .put("reason", "3 missed heartbeats").put("downtime_s", 45.0)
                .put("sessions_preserved_pct", 80.0),
        ))
        .put("exit", JSONObject()
            .put("ip", "198.51.100.23").put("country", "US")
            .put("healthy", true).put("checked_at", 999_500L).put("ip_stable", true))

    @Test fun `status parses with measured values intact`() {
        val st = HaApi.HaStatus.fromJson(statusJson())
        assertEquals(2, st.tunnels.size)
        val a = st.tunnel("A")!!
        assertEquals("wireguard", a.protocol)
        assertEquals("udp", a.transportFamily)
        assertEquals(141L, a.rttMs)
        assertEquals(0.2, a.lossPct!!, 1e-9)
        assertTrue(a.keepaliveOk)
        assertEquals("A", st.primary)
        assertEquals("hot_standby", st.mode)
        assertEquals(listOf("hot_standby"), st.availableModes)
        assertTrue(st.autoRecovery)
        assertEquals(3, st.heartbeatIntervalS)
        assertEquals(2L, st.failoverCount)
        assertEquals(75.0, st.totalDowntimeS, 1e-9)
        assertEquals(1, st.recentFailovers.size)
        val e = st.recentFailovers[0]
        assertEquals("A", e.from)
        assertEquals("B", e.to)
        assertEquals(45.0, e.downtimeS, 1e-9)
        val exit = st.exit!!
        assertEquals("198.51.100.23", exit.ip)
        assertTrue(exit.healthy)
        assertTrue(exit.ipStable)
    }

    @Test fun `missing optionals degrade gracefully`() {
        val st = HaApi.HaStatus.fromJson(JSONObject())
        assertTrue(st.tunnels.isEmpty())
        assertNull(st.primary)
        assertEquals("hot_standby", st.mode)
        assertEquals(listOf("hot_standby"), st.availableModes)
        assertNull(st.exit)
        val t = HaApi.HaTunnel.fromJson(JSONObject().put("id", "A"))
        assertEquals("down", t.state) // unknown -> down, fail-closed
        assertNull(t.rttMs)
        assertFalse(t.isPrimaryCandidate)
    }

    @Test fun `down tunnel is never a primary candidate`() {
        val down = HaApi.HaTunnel.fromJson(JSONObject().put("id", "B").put("state", "down"))
        assertFalse(down.isPrimaryCandidate)
        listOf("up", "degraded", "standby").forEach { s ->
            assertTrue(HaApi.HaTunnel.fromJson(JSONObject().put("id", "A").put("state", s)).isPrimaryCandidate)
        }
    }

    @Test fun `downtime formats from measured values`() {
        assertEquals("0s", HaApi.formatDowntime(0.0))
        assertEquals("45s", HaApi.formatDowntime(45.0))
        assertEquals("3m 12s", HaApi.formatDowntime(192.0))
        assertEquals("2m", HaApi.formatDowntime(120.0))
        assertEquals("1h 2m", HaApi.formatDowntime(3720.0))
        assertEquals("—", HaApi.formatDowntime(-1.0))
    }

    @Test fun `formatAgo is clock-injected and honest`() {
        val now = 200_000_000L
        assertEquals("never", HaApi.formatAgo(0, now))
        assertEquals("just now", HaApi.formatAgo(now - 10_000, now))
        assertEquals("12 min ago", HaApi.formatAgo(now - 12 * 60_000, now))
        assertEquals("3 h ago", HaApi.formatAgo(now - 3 * 3_600_000, now))
        assertEquals("2 d ago", HaApi.formatAgo(now - 2 * 86_400_000, now))
    }

    @Test fun `unknown modes are shown as-is, never silently mapped`() {
        assertEquals("Hot standby", HaApi.modeLabel("hot_standby"))
        assertEquals("Active-active", HaApi.modeLabel("active_active"))
        assertEquals("weird_future_mode", HaApi.modeLabel("weird_future_mode"))
    }
}
