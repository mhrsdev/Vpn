package com.zeronet.mobile.ui.admin

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import com.zeronet.mobile.R
import com.zeronet.mobile.ui.components.PrimaryButton
import com.zeronet.mobile.ui.components.ToggleRow
import com.zeronet.mobile.ui.components.TonalButton
import com.zeronet.mobile.ui.components.ZeroCard
import com.zeronet.mobile.ui.components.ZeroChip
import com.zeronet.mobile.ui.components.ZeroTextField
import com.zeronet.mobile.ui.theme.ZeroTheme

/**
 * Inter-Server High Availability: the dual always-on Iran→USA leg
 * (owner HA addendum, binding).
 *
 * The panel mirrors the backend's measured state. Downtime shown is
 * MEASURED — the UI never claims "zero downtime": new connections switch
 * fast, existing sessions are preserved where possible, and true lossless
 * is not asserted without measured proof.
 */
@Composable
fun HaSection(model: AdminModel) {
    val c = ZeroTheme.colors
    HaTitle(stringResource(R.string.ha_title))
    val st = model.haStatus
    if (st == null) {
        if (!model.loading) {
            Text(
                stringResource(R.string.ha_no_status),
                style = MaterialTheme.typography.bodyMedium,
                color = c.muted,
            )
            Spacer(Modifier.height(8.dp))
            TonalButton(stringResource(R.string.admin_refresh), model::refreshHa, Modifier.fillMaxWidth())
        }
        return
    }
    val now = System.currentTimeMillis()

    // Tunnel A / B.
    HaTitle(stringResource(R.string.ha_tunnels))
    st.tunnels.forEach { t ->
        HaTunnelCard(model, st, t, now)
        Spacer(Modifier.height(8.dp))
    }

    // Summary: primary, mode, measured failover history.
    HaTitle(stringResource(R.string.ha_summary))
    ZeroCard(Modifier.fillMaxWidth()) {
        HaRow(stringResource(R.string.ha_primary), st.primary?.let { "Tunnel $it" } ?: "—")
        HaRow(
            stringResource(R.string.ha_last_failover),
            HaApi.formatAgo(st.lastFailoverAt, now),
        )
        HaRow(stringResource(R.string.ha_failover_count), st.failoverCount.toString())
        HaRow(
            stringResource(R.string.ha_downtime),
            HaApi.formatDowntime(st.totalDowntimeS) + " " + stringResource(R.string.ha_measured),
        )
        Spacer(Modifier.height(4.dp))
        Text(
            stringResource(R.string.ha_honesty),
            style = MaterialTheme.typography.bodySmall,
            color = c.muted,
        )
    }
    Spacer(Modifier.height(12.dp))

    // Mode switch — only modes the backend declares available are offered.
    HaTitle(stringResource(R.string.ha_mode))
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        st.availableModes.forEach { m ->
            ZeroChip(HaApi.modeLabel(m), { model.setHaMode(m) }, selected = st.mode == m)
        }
    }
    if (!st.availableModes.contains("active_active")) {
        Spacer(Modifier.height(4.dp))
        Text(
            stringResource(R.string.ha_active_active_note),
            style = MaterialTheme.typography.bodySmall,
            color = c.muted,
        )
    }
    Spacer(Modifier.height(12.dp))

    // Recent failovers, with what was actually measured.
    if (st.recentFailovers.isNotEmpty()) {
        HaTitle(stringResource(R.string.ha_history))
        st.recentFailovers.take(5).forEach { e ->
            ZeroCard(Modifier.fillMaxWidth().padding(bottom = 8.dp)) {
                Text(
                    stringResource(R.string.ha_event_title, e.from, e.to, HaApi.formatAgo(e.at, now)),
                    style = MaterialTheme.typography.labelLarge,
                    color = c.text,
                )
                if (e.reason.isNotEmpty()) {
                    Spacer(Modifier.height(2.dp))
                    Text(e.reason, style = MaterialTheme.typography.bodySmall, color = c.muted)
                }
                Spacer(Modifier.height(2.dp))
                Text(
                    stringResource(
                        R.string.ha_event_detail,
                        HaApi.formatDowntime(e.downtimeS),
                        e.sessionsPreservedPct?.let { "${it.toInt()}%" } ?: "—",
                    ),
                    style = MaterialTheme.typography.bodySmall,
                    color = c.muted,
                )
            }
        }
        Spacer(Modifier.height(4.dp))
    }

    // Heartbeat + threshold + auto-recovery.
    HaTitle(stringResource(R.string.ha_settings))
    HaSettingsForm(model, st)
    Spacer(Modifier.height(12.dp))

    // USA exit health: the fixed exit IP must survive failovers unchanged.
    HaTitle(stringResource(R.string.ha_exit))
    val exit = st.exit
    if (exit == null) {
        Text(stringResource(R.string.ha_no_exit), style = MaterialTheme.typography.bodySmall, color = c.muted)
    } else {
        ZeroCard(Modifier.fillMaxWidth()) {
            HaRow(stringResource(R.string.ha_exit_ip), exit.ip.ifEmpty { "—" })
            exit.country?.let { HaRow(stringResource(R.string.sr_result_exit), it) }
            HaRow(
                stringResource(R.string.ha_exit_health),
                if (exit.healthy) stringResource(R.string.ha_healthy) else stringResource(R.string.ha_unhealthy),
                valueColor = if (exit.healthy) c.accent else c.err,
            )
            HaRow(
                stringResource(R.string.ha_exit_stable),
                if (exit.ipStable) stringResource(R.string.ha_yes) else stringResource(R.string.ha_no),
                valueColor = if (exit.ipStable) c.accent else c.warn,
            )
            HaRow(
                stringResource(R.string.ha_checked),
                HaApi.formatAgo(exit.checkedAt, now),
            )
        }
    }
}

@Composable
private fun HaTitle(text: String) {
    Text(text, style = MaterialTheme.typography.titleSmall, color = ZeroTheme.colors.text, modifier = Modifier.semantics { heading() })
    Spacer(Modifier.height(8.dp))
}

@Composable
private fun HaTunnelCard(model: AdminModel, st: HaApi.HaStatus, t: HaApi.HaTunnel, now: Long) {
    val c = ZeroTheme.colors
    val isPrimary = st.primary == t.id
    val stateColor = when (t.state) {
        "up" -> c.accent
        "degraded" -> c.warn
        "standby" -> c.muted
        else -> c.err
    }
    val stateLabel = when (t.state) {
        "up" -> stringResource(R.string.ha_state_up)
        "degraded" -> stringResource(R.string.ha_state_degraded)
        "standby" -> stringResource(R.string.ha_state_standby)
        else -> stringResource(R.string.ha_state_down)
    }
    ZeroCard(Modifier.fillMaxWidth()) {
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        stringResource(R.string.ha_tunnel, t.id),
                        style = MaterialTheme.typography.labelLarge,
                        color = c.text,
                    )
                    if (isPrimary) {
                        Text(
                            " · " + stringResource(R.string.ha_primary_badge),
                            style = MaterialTheme.typography.labelMedium,
                            color = c.accent,
                        )
                    }
                }
                Text(
                    t.protocol + (t.transportFamily?.let { " · $it" } ?: ""),
                    style = MaterialTheme.typography.bodySmall,
                    color = c.muted,
                )
            }
            Text(stateLabel, style = MaterialTheme.typography.labelMedium, color = stateColor)
        }
        Spacer(Modifier.height(8.dp))
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(16.dp)) {
            HaMetric(
                stringResource(R.string.ha_rtt),
                t.rttMs?.let { "${it} ms" } ?: "—",
            )
            HaMetric(
                stringResource(R.string.ha_loss),
                t.lossPct?.let { "%.1f%%".format(it) } ?: "—",
            )
            t.jitterMs?.let { HaMetric(stringResource(R.string.ha_jitter), "$it ms") }
        }
        Spacer(Modifier.height(4.dp))
        HaRow(
            stringResource(R.string.ha_keepalive),
            if (t.keepaliveOk) stringResource(R.string.ha_healthy) else stringResource(R.string.ha_unhealthy),
            valueColor = if (t.keepaliveOk) c.accent else c.err,
        )
        HaRow(
            stringResource(R.string.ha_last_beat),
            HaApi.formatAgo(t.lastHeartbeatAt, now),
        )
        HaRow(
            stringResource(R.string.ha_traffic),
            "↑ ${HaApi.formatBytes(t.bytesUp)}  ↓ ${HaApi.formatBytes(t.bytesDown)}",
        )
        if (!isPrimary) {
            Spacer(Modifier.height(8.dp))
            TonalButton(
                stringResource(R.string.ha_make_primary),
                { model.setHaPrimary(t.id) },
                Modifier.fillMaxWidth(),
                enabled = t.isPrimaryCandidate,
            )
            if (!t.isPrimaryCandidate) {
                Spacer(Modifier.height(4.dp))
                Text(
                    stringResource(R.string.ha_not_candidate),
                    style = MaterialTheme.typography.bodySmall,
                    color = c.warn,
                )
            }
        }
    }
}

@Composable
private fun HaMetric(label: String, value: String) {
    val c = ZeroTheme.colors
    Column {
        Text(label, style = MaterialTheme.typography.labelSmall, color = c.muted)
        Text(value, style = MaterialTheme.typography.bodyLarge, color = c.text)
    }
}

@Composable
private fun HaRow(label: String, value: String, valueColor: androidx.compose.ui.graphics.Color = ZeroTheme.colors.text) {
    val c = ZeroTheme.colors
    Row(Modifier.fillMaxWidth().padding(vertical = 2.dp)) {
        Text(label, style = MaterialTheme.typography.bodySmall, color = c.muted, modifier = Modifier.weight(1f))
        Text(value, style = MaterialTheme.typography.bodySmall, color = valueColor)
    }
}

@Composable
private fun HaSettingsForm(model: AdminModel, st: HaApi.HaStatus) {
    val c = ZeroTheme.colors
    var interval by remember(st) { mutableStateOf(st.heartbeatIntervalS.toString()) }
    var threshold by remember(st) { mutableStateOf(st.failoverThresholdMissed.toString()) }
    var autoRecovery by remember(st) { mutableStateOf(st.autoRecovery) }
    ZeroCard(Modifier.fillMaxWidth()) {
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Column(Modifier.weight(1f)) {
                Text(stringResource(R.string.ha_heartbeat), style = MaterialTheme.typography.labelMedium, color = c.muted)
                ZeroTextField(
                    interval,
                    { interval = it.filter(Char::isDigit).take(2) },
                    keyboardType = KeyboardType.Number,
                    placeholder = "3",
                )
                Text(stringResource(R.string.ha_heartbeat_hint), style = MaterialTheme.typography.bodySmall, color = c.muted)
            }
            Column(Modifier.weight(1f)) {
                Text(stringResource(R.string.ha_threshold), style = MaterialTheme.typography.labelMedium, color = c.muted)
                ZeroTextField(
                    threshold,
                    { threshold = it.filter(Char::isDigit).take(2) },
                    keyboardType = KeyboardType.Number,
                    placeholder = "3",
                )
                Text(stringResource(R.string.ha_threshold_hint), style = MaterialTheme.typography.bodySmall, color = c.muted)
            }
        }
        Spacer(Modifier.height(8.dp))
        ToggleRow(
            title = stringResource(R.string.ha_auto_recovery),
            checked = autoRecovery,
            onCheckedChange = { autoRecovery = it },
            subtitle = stringResource(R.string.ha_auto_recovery_hint),
        )
        Spacer(Modifier.height(8.dp))
        PrimaryButton(
            stringResource(R.string.action_save),
            {
                model.saveHaSettings(
                    interval.toIntOrNull()?.coerceIn(1, 60) ?: st.heartbeatIntervalS,
                    threshold.toIntOrNull()?.coerceIn(1, 20) ?: st.failoverThresholdMissed,
                    autoRecovery,
                )
            },
            Modifier.fillMaxWidth(),
            enabled = interval.isNotBlank() && threshold.isNotBlank(),
        )
    }
}
