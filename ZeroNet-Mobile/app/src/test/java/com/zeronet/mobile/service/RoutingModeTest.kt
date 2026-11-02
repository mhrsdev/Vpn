package com.zeronet.mobile.service

import com.zeronet.mobile.model.ConnectionProfile
import com.zeronet.mobile.model.Server
import com.zeronet.mobile.model.pairAware
import com.zeronet.mobile.model.wire
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The per-mode server filter (the pure half of `Engine.suits`; country
 * exclusion and ladder relaxation stay in the engine).
 */
class RoutingModeTest {

    private fun server(
        protocol: String = "vless",
        security: String = "reality",
        transport: String = "tcp",
        favorite: Boolean = false,
    ) = Server(
        key = "k", link = "$protocol://x", name = "s", protocol = protocol,
        transport = transport, security = security, host = "1.2.3.4", port = 443,
        country = "DE", source = "user", favorite = favorite,
    )

    @Test
    fun `balanced keeps the encrypted-only rule of normal`() {
        assertTrue(suitsProfile(server(), ConnectionProfile.Balanced, null, null))
        assertTrue(suitsProfile(server(), ConnectionProfile.Normal, null, null))
        assertFalse(suitsProfile(server(protocol = "ss", security = "none"), ConnectionProfile.Balanced, null, null))
    }

    @Test
    fun `lowest latency takes anything`() {
        assertTrue(suitsProfile(server(protocol = "ss", security = "none"), ConnectionProfile.LowestLatency, null, null))
        assertTrue(suitsProfile(server(protocol = "socks", security = "none"), ConnectionProfile.LowestLatency, null, null))
    }

    @Test
    fun `max stability keeps encrypted transports but skips dns-tunnelled ones`() {
        assertTrue(suitsProfile(server(), ConnectionProfile.MaxStability, null, null))
        assertFalse(suitsProfile(server(protocol = "masterdns", security = "none"), ConnectionProfile.MaxStability, null, null))
        assertFalse(suitsProfile(server(protocol = "ss", security = "none"), ConnectionProfile.MaxStability, null, null))
    }

    @Test
    fun `gaming skips cdn and websocket transports`() {
        assertTrue(suitsProfile(server(protocol = "hysteria2", security = "none", transport = "udp"), ConnectionProfile.Gaming, null, null))
        assertFalse(suitsProfile(server(protocol = "vless", security = "tls", transport = "ws"), ConnectionProfile.Gaming, null, null))
    }

    @Test
    fun `manual only uses pinned servers`() {
        val plain = server()
        assertFalse(suitsProfile(plain, ConnectionProfile.Manual, null, null))
        assertTrue(suitsProfile(plain.copy(favorite = true), ConnectionProfile.Manual, null, null))
        // A locked pair gateway suits; an unlocked one does not.
        assertTrue(suitsProfile(plain, ConnectionProfile.Manual, "pair-abc", "pair-abc"))
        assertFalse(suitsProfile(plain, ConnectionProfile.Manual, "pair-abc", "pair-other"))
        assertFalse(suitsProfile(plain, ConnectionProfile.Manual, null, "pair-abc"))
    }

    @Test
    fun `fixed us exit only admits pair gateways`() {
        val plain = server()
        assertFalse(suitsProfile(plain, ConnectionProfile.FixedUsExit, null, null))
        assertTrue(suitsProfile(plain, ConnectionProfile.FixedUsExit, null, "pair-abc"))
    }

    @Test
    fun `wire spellings match the frozen routing contract`() {
        assertTrue(ConnectionProfile.Balanced.wire == "balanced")
        assertTrue(ConnectionProfile.Normal.wire == "balanced")
        assertTrue(ConnectionProfile.LowestLatency.wire == "lowest-latency")
        assertTrue(ConnectionProfile.MaxStability.wire == "max-stability")
        assertTrue(ConnectionProfile.Gaming.wire == "gaming")
        assertTrue(ConnectionProfile.Manual.wire == "manual")
        assertTrue(ConnectionProfile.FixedUsExit.wire == "fixed-us-exit")
    }

    @Test
    fun `pair-aware modes emit the routing block, fast and legacy do not`() {
        assertTrue(ConnectionProfile.Balanced.pairAware)
        assertTrue(ConnectionProfile.FixedUsExit.pairAware)
        assertTrue(ConnectionProfile.Manual.pairAware)
        assertFalse(ConnectionProfile.Fast.pairAware)
        assertFalse(ConnectionProfile.Legacy.pairAware)
    }
}
