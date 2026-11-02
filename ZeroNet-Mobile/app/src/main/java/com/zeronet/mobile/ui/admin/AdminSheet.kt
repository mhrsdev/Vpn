package com.zeronet.mobile.ui.admin

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.LinearProgressIndicator
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
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import com.zeronet.mobile.R
import com.zeronet.mobile.model.RouteLeg
import com.zeronet.mobile.ui.components.NavRow
import com.zeronet.mobile.ui.components.PrimaryButton
import com.zeronet.mobile.ui.components.QrCode
import com.zeronet.mobile.ui.components.QrScanner
import com.zeronet.mobile.ui.components.ToggleRow
import com.zeronet.mobile.ui.components.TonalButton
import com.zeronet.mobile.ui.components.ZeroCard
import com.zeronet.mobile.ui.components.ZeroChip
import com.zeronet.mobile.ui.components.ZeroSheet
import com.zeronet.mobile.ui.components.ZeroTextField
import com.zeronet.mobile.ui.theme.ZeroTheme
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * The management UI: servers, users, devices, subscriptions, route
 * history, DNS policy and backup — all against the pair's `/api/v1`
 * (Design C) through [AdminModel]. The admin bridge is the routing agent's
 * `adminCall`; until it lands, screens show its honest error.
 */
@Composable
fun AdminSheet(model: AdminModel) {
    ZeroSheet(
        visible = model.open,
        onDismiss = model::close,
        title = stringResource(R.string.admin_title),
    ) {
        val c = ZeroTheme.colors
        Column(
            Modifier
                .weight(1f, fill = false)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 24.dp),
        ) {
            SectionNav(model)
            Spacer(Modifier.height(12.dp))
            if (model.loading) {
                LinearProgressIndicator(Modifier.fillMaxWidth())
                Spacer(Modifier.height(8.dp))
            }
            model.error?.let {
                Text(it, color = c.err, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite })
                Spacer(Modifier.height(8.dp))
            }
            when (model.screen) {
                AdminScreen.Dashboard -> DashboardSection(model)
                AdminScreen.Users -> UsersSection(model)
                AdminScreen.Devices -> DevicesSection(model)
                AdminScreen.Subscriptions -> SubscriptionsSection(model)
                AdminScreen.HuaweiRouter -> HuaweiRouterSection(model)
                AdminScreen.SmartRouting -> SmartRoutingSection(model)
                AdminScreen.Ha -> HaSection(model)
                AdminScreen.RouteHistory -> RouteHistorySection(model)
                AdminScreen.Dns -> DnsSection(model)
                AdminScreen.Backup -> BackupSection(model)
            }
            Spacer(Modifier.height(24.dp))
        }
        // QR overlay: issued credentials or a subscription link.
        model.qrText?.let { text ->
            ZeroSheet(visible = true, onDismiss = { model.qrText = null }, title = stringResource(R.string.admin_qr_title)) {
                Column(Modifier.padding(horizontal = 24.dp)) {
                    QrCode(text, stringResource(R.string.admin_qr_title))
                    Spacer(Modifier.height(12.dp))
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        TonalButton(stringResource(R.string.ms_copy), { model.copy(text, true) }, Modifier.weight(1f))
                        TonalButton(stringResource(R.string.ms_share), {
                            model.startIntent(android.content.Intent(android.content.Intent.ACTION_SEND).apply {
                                type = "text/plain"; putExtra(android.content.Intent.EXTRA_TEXT, text)
                            })
                        }, Modifier.weight(1f))
                    }
                    Spacer(Modifier.height(24.dp))
                }
            }
        }
    }
}

@Composable
private fun SectionNav(model: AdminModel) {
    val sections = listOf(
        AdminScreen.Dashboard to R.string.admin_nav_dashboard,
        AdminScreen.Users to R.string.admin_nav_users,
        AdminScreen.Devices to R.string.admin_nav_devices,
        AdminScreen.Subscriptions to R.string.admin_nav_subs,
        AdminScreen.HuaweiRouter to R.string.admin_nav_huawei,
        AdminScreen.SmartRouting to R.string.admin_nav_smart,
        AdminScreen.Ha to R.string.admin_nav_ha,
        AdminScreen.RouteHistory to R.string.admin_nav_routes,
        AdminScreen.Dns to R.string.admin_nav_dns,
        AdminScreen.Backup to R.string.admin_nav_backup,
    )
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.fillMaxWidth()) {
        sections.forEach { (screen, label) ->
            ZeroChip(stringResource(label), { model.go(screen) }, selected = model.screen == screen)
        }
    }
}

@Composable
private fun SectionTitle(text: String) {
    Text(text, style = MaterialTheme.typography.titleSmall, color = ZeroTheme.colors.text, modifier = Modifier.semantics { heading() })
    Spacer(Modifier.height(8.dp))
}

// --------------------------------------------------------------- dashboard

@Composable
private fun DashboardSection(model: AdminModel) {
    SectionTitle(stringResource(R.string.admin_nav_dashboard))
    model.servers.forEach { s ->
        ZeroCard(Modifier.fillMaxWidth().padding(bottom = 8.dp)) {
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text(
                        if (s.role == "gateway") stringResource(R.string.pair_gateway) else stringResource(R.string.pair_exit),
                        style = MaterialTheme.typography.labelLarge,
                        color = ZeroTheme.colors.text,
                    )
                    Text(s.host, style = MaterialTheme.typography.bodySmall, color = ZeroTheme.colors.muted)
                    s.tunnelState?.let { Text(stringResource(R.string.admin_tunnel_state, it, s.tunnelRttMs?.toString() ?: "—"), style = MaterialTheme.typography.bodySmall, color = ZeroTheme.colors.muted) }
                }
                Text(
                    if (s.engineReachable) stringResource(R.string.admin_up) else stringResource(R.string.admin_down),
                    color = if (s.engineReachable) ZeroTheme.colors.accent else ZeroTheme.colors.err,
                    style = MaterialTheme.typography.labelLarge,
                )
            }
        }
    }
    model.exitIp?.let {
        ZeroCard(Modifier.fillMaxWidth()) {
            Text(stringResource(R.string.admin_exit_ip, it), style = MaterialTheme.typography.bodyMedium, color = ZeroTheme.colors.text)
        }
        Spacer(Modifier.height(8.dp))
    }
    TonalButton(stringResource(R.string.admin_refresh), model::refreshDashboard, Modifier.fillMaxWidth())
}

// ------------------------------------------------------------------- users

@Composable
private fun UsersSection(model: AdminModel) {
    SectionTitle(stringResource(R.string.admin_nav_users))
    var name by remember { mutableStateOf("") }
    var quotaGb by remember { mutableStateOf("") }
    var speedMbps by remember { mutableStateOf("") }
    var maxDevices by remember { mutableStateOf("") }
    ZeroCard(Modifier.fillMaxWidth()) {
        ZeroTextField(name, { name = it }, placeholder = stringResource(R.string.admin_user_name))
        Spacer(Modifier.height(8.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            ZeroTextField(quotaGb, { quotaGb = it.filter(Char::isDigit) }, placeholder = stringResource(R.string.admin_quota_gb), keyboardType = KeyboardType.Number, modifier = Modifier.weight(1f))
            ZeroTextField(speedMbps, { speedMbps = it.filter(Char::isDigit) }, placeholder = stringResource(R.string.admin_speed_mbps), keyboardType = KeyboardType.Number, modifier = Modifier.weight(1f))
            ZeroTextField(maxDevices, { maxDevices = it.filter(Char::isDigit) }, placeholder = stringResource(R.string.admin_max_devices), keyboardType = KeyboardType.Number, modifier = Modifier.weight(1f))
        }
        Spacer(Modifier.height(8.dp))
        PrimaryButton(
            stringResource(R.string.admin_create_user),
            {
                model.createUser(name.trim(), quotaGb.toLongOrNull(), speedMbps.toIntOrNull(), maxDevices.toIntOrNull())
                name = ""; quotaGb = ""; speedMbps = ""; maxDevices = ""
            },
            Modifier.fillMaxWidth(),
            enabled = name.isNotBlank(),
        )
    }
    Spacer(Modifier.height(12.dp))
    model.users.forEach { u ->
        ZeroCard(Modifier.fillMaxWidth().padding(bottom = 8.dp)) {
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text(u.name, style = MaterialTheme.typography.labelLarge, color = ZeroTheme.colors.text)
                    u.note?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = ZeroTheme.colors.muted) }
                    Text(
                        listOfNotNull(
                            u.quotaBytes?.let { stringResource(R.string.admin_quota_gb_value, it / 1_000_000_000L) },
                            u.quotaMbps?.let { stringResource(R.string.admin_speed_mbps_value, it) },
                            u.maxDevices?.let { stringResource(R.string.admin_max_devices_value, it) },
                        ).joinToString(" · ").ifEmpty { stringResource(R.string.admin_no_limits) },
                        style = MaterialTheme.typography.bodySmall,
                        color = ZeroTheme.colors.muted,
                    )
                }
                Text(
                    if (u.enabled) stringResource(R.string.admin_enabled) else stringResource(R.string.admin_disabled),
                    color = if (u.enabled) ZeroTheme.colors.accent else ZeroTheme.colors.err,
                    style = MaterialTheme.typography.labelMedium,
                )
            }
            Spacer(Modifier.height(8.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                TonalButton(
                    stringResource(if (u.enabled) R.string.admin_disable else R.string.admin_enable),
                    { model.setUserEnabled(u, !u.enabled) },
                    Modifier.weight(1f),
                )
                TonalButton(stringResource(R.string.admin_devices), { model.refreshDevices(u.id); model.go(AdminScreen.Devices) }, Modifier.weight(1f))
                TonalButton(stringResource(R.string.admin_delete), { model.deleteUser(u) }, Modifier.weight(1f))
            }
        }
    }
}

// ----------------------------------------------------------------- devices

@Composable
private fun DevicesSection(model: AdminModel) {
    SectionTitle(stringResource(R.string.admin_nav_devices))
    var userId by remember { mutableStateOf("") }
    var label by remember { mutableStateOf("") }
    if (model.users.isNotEmpty()) {
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            model.users.forEach { u ->
                ZeroChip(u.name, { userId = u.id; model.refreshDevices(u.id) }, selected = userId == u.id)
            }
        }
        Spacer(Modifier.height(12.dp))
    } else {
        ZeroTextField(userId, { userId = it }, placeholder = stringResource(R.string.admin_user_id))
        Spacer(Modifier.height(8.dp))
    }
    ZeroCard(Modifier.fillMaxWidth()) {
        ZeroTextField(label, { label = it }, placeholder = stringResource(R.string.admin_device_label))
        Spacer(Modifier.height(8.dp))
        PrimaryButton(
            stringResource(R.string.admin_issue_device),
            { model.issueDevice(userId.trim(), label.trim()); label = "" },
            Modifier.fillMaxWidth(),
            enabled = userId.isNotBlank() && label.isNotBlank(),
        )
    }
    model.lastCredentials?.let { creds ->
        Spacer(Modifier.height(12.dp))
        ZeroCard(Modifier.fillMaxWidth()) {
            Text(stringResource(R.string.admin_credentials_once), style = MaterialTheme.typography.labelLarge, color = ZeroTheme.colors.warn)
            Spacer(Modifier.height(8.dp))
            creds.forEach { c ->
                Text("${c.protocol} · ${c.inboundTag}", style = MaterialTheme.typography.bodySmall, color = ZeroTheme.colors.muted)
                QrCode(c.link.ifEmpty { c.qrSvg }, c.inboundTag)
                Spacer(Modifier.height(8.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    TonalButton(stringResource(R.string.ms_copy), { model.copy(c.link, true) })
                }
                Spacer(Modifier.height(8.dp))
            }
            TonalButton(stringResource(R.string.admin_dismiss), model::clearCredentials, Modifier.fillMaxWidth())
        }
    }
    Spacer(Modifier.height(12.dp))
    model.devices.forEach { d ->
        ZeroCard(Modifier.fillMaxWidth().padding(bottom = 8.dp)) {
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text(d.label.ifEmpty { d.id.take(8) }, style = MaterialTheme.typography.labelLarge, color = ZeroTheme.colors.text)
                    Text(
                        stringResource(R.string.admin_device_traffic, d.up / 1_000_000L, d.down / 1_000_000L),
                        style = MaterialTheme.typography.bodySmall,
                        color = ZeroTheme.colors.muted,
                    )
                }
                Text(
                    if (d.enabled) stringResource(R.string.admin_enabled) else stringResource(R.string.admin_disabled),
                    color = if (d.enabled) ZeroTheme.colors.accent else ZeroTheme.colors.err,
                    style = MaterialTheme.typography.labelMedium,
                )
            }
            Spacer(Modifier.height(8.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                TonalButton(stringResource(R.string.admin_reissue), { model.reissueDevice(d) }, Modifier.weight(1f))
                TonalButton(stringResource(R.string.admin_revoke), { model.revokeDevice(d) }, Modifier.weight(1f))
            }
        }
    }
}

// ----------------------------------------------------------- subscriptions

@Composable
private fun SubscriptionsSection(model: AdminModel) {
    SectionTitle(stringResource(R.string.admin_nav_subs))
    var deviceId by remember { mutableStateOf("") }
    var extName by remember { mutableStateOf("") }
    var extBody by remember { mutableStateOf("") }
    var scanning by remember { mutableStateOf(false) }
    if (scanning) {
        QrScanner(onResult = { extBody = it; scanning = false }, onCancel = { scanning = false })
        Spacer(Modifier.height(8.dp))
    }
    ZeroCard(Modifier.fillMaxWidth()) {
        Text(stringResource(R.string.admin_personal_sub), style = MaterialTheme.typography.labelLarge, color = ZeroTheme.colors.text)
        Spacer(Modifier.height(8.dp))
        ZeroTextField(deviceId, { deviceId = it }, placeholder = stringResource(R.string.admin_device_id))
        Spacer(Modifier.height(8.dp))
        PrimaryButton(
            stringResource(R.string.admin_create_sub),
            { model.createPersonalSubscription(deviceId.trim(), null); deviceId = "" },
            Modifier.fillMaxWidth(),
            enabled = deviceId.isNotBlank(),
        )
    }
    Spacer(Modifier.height(12.dp))
    ZeroCard(Modifier.fillMaxWidth()) {
        Text(stringResource(R.string.admin_external_sub), style = MaterialTheme.typography.labelLarge, color = ZeroTheme.colors.text)
        Spacer(Modifier.height(8.dp))
        ZeroTextField(extName, { extName = it }, placeholder = stringResource(R.string.admin_sub_name))
        Spacer(Modifier.height(8.dp))
        ZeroTextField(extBody, { extBody = it }, placeholder = stringResource(R.string.admin_sub_body), singleLine = false, minLines = 3, maxLines = 6)
        Spacer(Modifier.height(8.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            PrimaryButton(
                stringResource(R.string.admin_import_sub),
                { model.importExternalSubscription(extName.trim(), extBody.trim()); extName = ""; extBody = "" },
                Modifier.weight(1f),
                enabled = extName.isNotBlank() && extBody.isNotBlank(),
            )
            TonalButton(stringResource(R.string.admin_scan), { scanning = true }, Modifier.weight(1f))
        }
    }
    Spacer(Modifier.height(12.dp))
    model.subscriptions.forEach { s ->
        ZeroCard(Modifier.fillMaxWidth().padding(bottom = 8.dp)) {
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text(s.name ?: s.id.take(8), style = MaterialTheme.typography.labelLarge, color = ZeroTheme.colors.text)
                    Text(
                        if (s.managed) stringResource(R.string.admin_sub_managed) else stringResource(R.string.admin_sub_external),
                        style = MaterialTheme.typography.bodySmall,
                        color = ZeroTheme.colors.muted,
                    )
                }
                TonalButton(stringResource(R.string.admin_qr), { model.qrText = s.qrText })
            }
            Spacer(Modifier.height(8.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                if (s.managed) TonalButton(stringResource(R.string.admin_rotate), { model.rotateSubscription(s) }, Modifier.weight(1f))
                TonalButton(stringResource(R.string.admin_revoke), { model.revokeSubscription(s) }, Modifier.weight(1f))
            }
        }
    }
}

// ------------------------------------------------------------ route history

private val dateFormat = SimpleDateFormat("MMM d, HH:mm", Locale.US)

@Composable
private fun RouteHistorySection(model: AdminModel) {
    SectionTitle(stringResource(R.string.admin_nav_routes))
    if (model.routeEvents.isEmpty()) {
        Text(stringResource(R.string.admin_no_routes), style = MaterialTheme.typography.bodyMedium, color = ZeroTheme.colors.muted)
    }
    model.routeEvents.forEach { e ->
        ZeroCard(Modifier.fillMaxWidth().padding(bottom = 8.dp)) {
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text(
                        "${if (e.leg == RouteLeg.A) "Device→Iran" else "Iran→USA"}: ${e.from} → ${e.to}",
                        style = MaterialTheme.typography.labelLarge,
                        color = ZeroTheme.colors.text,
                    )
                    Text(e.reason, style = MaterialTheme.typography.bodySmall, color = ZeroTheme.colors.muted)
                }
                Text(dateFormat.format(Date(e.at)), style = MaterialTheme.typography.bodySmall, color = ZeroTheme.colors.muted)
            }
        }
    }
    Spacer(Modifier.height(8.dp))
    TonalButton(stringResource(R.string.admin_refresh), model::refreshRouteHistory, Modifier.fillMaxWidth())
}

// --------------------------------------------------------------------- dns

@Composable
private fun DnsSection(model: AdminModel) {
    SectionTitle(stringResource(R.string.admin_nav_dns))
    var mode by remember(model.dnsPolicy) { mutableStateOf(model.dnsPolicy?.mode ?: "auto") }
    var resolvers by remember(model.dnsPolicy) { mutableStateOf(model.dnsPolicy?.resolvers?.joinToString(", ") ?: "") }
    ToggleRow(stringResource(R.string.admin_dns_strict), mode == "strict", { mode = if (it) "strict" else "auto" })
    Spacer(Modifier.height(8.dp))
    ZeroTextField(resolvers, { resolvers = it }, placeholder = stringResource(R.string.admin_dns_resolvers), singleLine = false, minLines = 2, maxLines = 4)
    model.dnsPolicy?.note?.let {
        Spacer(Modifier.height(8.dp))
        Text(it, style = MaterialTheme.typography.bodySmall, color = ZeroTheme.colors.muted)
    }
    Spacer(Modifier.height(12.dp))
    PrimaryButton(
        stringResource(R.string.admin_save_dns),
        { model.saveDns(mode, resolvers.split(",").map { r -> r.trim() }.filter { it.isNotEmpty() }) },
        Modifier.fillMaxWidth(),
    )
}

// ------------------------------------------------------------------ backup

@Composable
private fun BackupSection(model: AdminModel) {
    SectionTitle(stringResource(R.string.admin_nav_backup))
    var passphrase by remember { mutableStateOf("") }
    var restoreText by remember { mutableStateOf("") }
    ZeroCard(Modifier.fillMaxWidth()) {
        ZeroTextField(
            passphrase,
            { passphrase = it },
            placeholder = stringResource(R.string.admin_passphrase),
            keyboardType = KeyboardType.Password,
            visualTransformation = PasswordVisualTransformation(),
        )
        Spacer(Modifier.height(8.dp))
        PrimaryButton(
            stringResource(R.string.admin_backup),
            { model.backup(passphrase) },
            Modifier.fillMaxWidth(),
            enabled = passphrase.isNotEmpty(),
        )
    }
    model.backupBlob?.let { blob ->
        Spacer(Modifier.height(12.dp))
        ZeroCard(Modifier.fillMaxWidth()) {
            Text(stringResource(R.string.admin_backup_ready), style = MaterialTheme.typography.labelLarge, color = ZeroTheme.colors.text)
            Spacer(Modifier.height(8.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                TonalButton(stringResource(R.string.ms_copy), { model.copy(blob, true) }, Modifier.weight(1f))
                TonalButton(stringResource(R.string.ms_share), {
                    model.startIntent(android.content.Intent(android.content.Intent.ACTION_SEND).apply {
                        type = "text/plain"; putExtra(android.content.Intent.EXTRA_TEXT, blob)
                    })
                }, Modifier.weight(1f))
            }
            Spacer(Modifier.height(8.dp))
            TonalButton(stringResource(R.string.admin_dismiss), model::clearBackup, Modifier.fillMaxWidth())
        }
    }
    Spacer(Modifier.height(12.dp))
    ZeroCard(Modifier.fillMaxWidth()) {
        Text(stringResource(R.string.admin_restore_title), style = MaterialTheme.typography.labelLarge, color = ZeroTheme.colors.text)
        Spacer(Modifier.height(8.dp))
        ZeroTextField(restoreText, { restoreText = it }, placeholder = stringResource(R.string.admin_restore_blob), singleLine = false, minLines = 3, maxLines = 5)
        Spacer(Modifier.height(8.dp))
        PrimaryButton(
            stringResource(R.string.admin_restore),
            { model.restore(restoreText.trim(), passphrase) },
            Modifier.fillMaxWidth(),
            enabled = restoreText.isNotBlank() && passphrase.isNotEmpty(),
        )
    }
}
