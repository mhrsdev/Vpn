package com.zeronet.mobile.ui.myserver

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import com.zeronet.mobile.R
import com.zeronet.mobile.data.MyServerStore
import com.zeronet.mobile.ui.components.NavRow
import com.zeronet.mobile.ui.components.PrimaryButton
import com.zeronet.mobile.ui.components.QrCode
import com.zeronet.mobile.ui.components.ToggleRow
import com.zeronet.mobile.ui.components.TonalButton
import com.zeronet.mobile.ui.components.ZeroCard
import com.zeronet.mobile.ui.components.ZeroChip
import com.zeronet.mobile.ui.components.ZeroSheet
import com.zeronet.mobile.ui.components.ZeroTextField
import com.zeronet.mobile.ui.theme.ZeroTheme

/**
 * The Iran/USA pair page: provision two servers and the encrypted tunnel
 * between them, then watch the tunnel's health. State lives in [PairModel];
 * every request goes through its injected `run` (the core's
 * `zero_provision::job` pair ops, Design A §6) — no new JNI.
 */
@Composable
fun PairSheet(model: PairModel, admin: com.zeronet.mobile.ui.admin.AdminModel? = null) {
    ZeroSheet(
        visible = model.open,
        onDismiss = model::back,
        title = stringResource(R.string.pair_title),
    ) {
        val c = ZeroTheme.colors
        Column(
            Modifier
                .weight(1f, fill = false)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 24.dp),
        ) {
            val screen = model.screen
            Text(
                titleForPair(screen),
                style = MaterialTheme.typography.titleLarge,
                color = c.text,
                modifier = Modifier.semantics { heading() },
            )
            Spacer(Modifier.height(12.dp))
            when (screen) {
                MsScreen.PairList -> PairListPage(model)
                MsScreen.PairForm -> PairFormPage(model)
                MsScreen.Busy -> Text(stringResource(R.string.ms_busy), color = c.muted, style = MaterialTheme.typography.bodyMedium)
                is MsScreen.PairIdentity -> PairIdentityPage(model, screen)
                is MsScreen.PairProgress -> PairProgressPage(model, screen)
                is MsScreen.PairResult -> PairResultPage(model, screen)
                is MsScreen.PairServer -> PairServerPage(model, screen)
                is MsScreen.ConfirmRemovePair -> ConfirmRemovePairPage(model, screen)
                else -> Unit
            }
            Spacer(Modifier.height(24.dp))
        }
    }
}

@Composable
private fun titleForPair(screen: MsScreen): String = stringResource(
    when (screen) {
        MsScreen.PairList, MsScreen.PairForm -> R.string.pair_form_title
        MsScreen.Busy -> R.string.pair_busy_title
        is MsScreen.PairIdentity -> R.string.pair_identity_title
        is MsScreen.PairProgress -> R.string.pair_progress_title
        is MsScreen.PairResult -> R.string.pair_result_title
        is MsScreen.PairServer -> R.string.pair_server_title
        is MsScreen.ConfirmRemovePair -> R.string.pair_remove_title
        else -> R.string.pair_title
    },
)

// -------------------------------------------------------------------- list

@Composable
private fun PairListPage(model: PairModel) {
    val c = ZeroTheme.colors
    model.notice?.let {
        Text(it, style = MaterialTheme.typography.bodyMedium, color = c.accent, modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite })
        Spacer(Modifier.height(12.dp))
    }
    if (model.pairs.isEmpty()) {
        Body(stringResource(R.string.pair_intro_1))
        Spacer(Modifier.height(8.dp))
        Body(stringResource(R.string.pair_intro_2), muted = true)
    } else {
        model.pairs.forEach { pair ->
            val up = model.tunnel[pair.pairId]?.up
            val status = when (up) {
                true -> stringResource(R.string.pair_tunnel_up)
                false -> stringResource(R.string.pair_tunnel_down)
                null -> null
            }
            NavRow(
                title = pair.name.ifEmpty { stringResource(R.string.pair_default_name) },
                subtitle = pair.record.optJSONObject("gateway")?.optString("host").orEmpty() +
                    " → " + pair.record.optJSONObject("exit")?.optString("host").orEmpty(),
                value = status,
                onClick = { model.openPair(pair.pairId) },
            )
        }
    }
    Spacer(Modifier.height(20.dp))
    PrimaryButton(stringResource(R.string.pair_add), model::startAdd, Modifier.fillMaxWidth())
}

// -------------------------------------------------------------------- form

@Composable
private fun PairFormPage(model: PairModel) {
    val form = model.form
    Field(R.string.pair_field_pair_name) {
        ZeroTextField(form.pairName, { form.pairName = it; form.error = null }, placeholder = stringResource(R.string.pair_default_name))
    }
    Spacer(Modifier.height(12.dp))
    ServerCard(stringResource(R.string.pair_iran), form.iran, model)
    Spacer(Modifier.height(12.dp))
    ServerCard(stringResource(R.string.pair_usa), form.usa, model)
    form.error?.let {
        Spacer(Modifier.height(12.dp))
        Text(it, color = ZeroTheme.colors.err, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite })
    }
    Spacer(Modifier.height(20.dp))
    PrimaryButton(stringResource(R.string.pair_connect), model::submitPair, Modifier.fillMaxWidth())
}

/** One end of the pair: the same fields as the single-server form, role-agnostic. */
@Composable
private fun ServerCard(roleTitle: String, form: ServerForm, model: PairModel) {
    val c = ZeroTheme.colors
    ZeroCard(Modifier.fillMaxWidth()) {
        Text(roleTitle, style = MaterialTheme.typography.titleSmall, color = c.text, modifier = Modifier.semantics { heading() })
        Field(R.string.ms_field_address) {
            ZeroTextField(form.address, { form.address = it; model.form.error = null }, placeholder = "203.0.113.7", keyboardType = KeyboardType.Uri)
        }
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Column(Modifier.weight(1f)) {
                Field(R.string.ms_field_port) {
                    ZeroTextField(form.port, { form.port = it.filter(Char::isDigit).take(5) }, keyboardType = KeyboardType.Number)
                }
            }
            Column(Modifier.weight(1f)) {
                Field(R.string.ms_field_user) { ZeroTextField(form.user, { form.user = it; model.form.error = null }) }
            }
        }
        Field(R.string.ms_login_with) {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                ZeroChip(stringResource(R.string.ms_login_password), { form.useKey = false; model.form.error = null }, selected = !form.useKey)
                ZeroChip(stringResource(R.string.ms_login_key), { form.useKey = true; model.form.error = null }, selected = form.useKey)
            }
        }
        if (form.useKey) KeyFields(form) else {
            Field(R.string.ms_field_password) {
                ZeroTextField(
                    form.password,
                    { form.password = it; model.form.error = null },
                    keyboardType = KeyboardType.Password,
                    visualTransformation = PasswordVisualTransformation(),
                )
            }
        }
        Spacer(Modifier.height(8.dp))
        Text(stringResource(R.string.ms_what_to_install), style = MaterialTheme.typography.labelLarge, color = c.muted)
        ToggleRow(stringResource(R.string.ms_service_reality), form.reality, { form.reality = it; model.form.error = null })
        ToggleRow(stringResource(R.string.ms_service_xhttp), form.xhttp, { form.xhttp = it; model.form.error = null })
    }
}

// --------------------------------------------------------------- identity

@Composable
private fun PairIdentityPage(model: PairModel, screen: MsScreen.PairIdentity) {
    val role = stringResource(
        if (screen.role == MsScreen.PairRole.Gateway) R.string.pair_trust_gateway else R.string.pair_trust_exit,
    )
    Body(stringResource(R.string.pair_trust_body, role))
    Spacer(Modifier.height(12.dp))
    ZeroCard {
        SelectionContainer {
            Text(screen.fingerprint, style = MaterialTheme.typography.bodyLarge, color = ZeroTheme.colors.accent)
        }
        Spacer(Modifier.height(4.dp))
        Small(screen.algorithm)
    }
    Spacer(Modifier.height(12.dp))
    Small(stringResource(R.string.ms_identity_help))
    Spacer(Modifier.height(20.dp))
    PrimaryButton(stringResource(R.string.ms_identity_yes), model::trustPairIdentity, Modifier.fillMaxWidth())
    Spacer(Modifier.height(8.dp))
    TonalButton(stringResource(R.string.ms_identity_no), model::back, Modifier.fillMaxWidth())
}

// --------------------------------------------------------------- progress

@Composable
private fun PairProgressPage(model: PairModel, screen: MsScreen.PairProgress) {
    val c = ZeroTheme.colors
    Text(
        stringResource(
            when (screen.phase) {
                MsScreen.PairPhase.IranInstall -> R.string.pair_phase_iran
                MsScreen.PairPhase.UsaInstall -> R.string.pair_phase_usa
                MsScreen.PairPhase.Linking -> R.string.pair_phase_linking
                MsScreen.PairPhase.Verifying -> R.string.pair_phase_verifying
            },
        ),
        style = MaterialTheme.typography.titleSmall,
        color = c.accent,
        modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite },
    )
    Spacer(Modifier.height(10.dp))
    Column(Modifier.semantics { liveRegion = LiveRegionMode.Polite }) {
        screen.steps.forEach { step ->
            Row(Modifier.padding(vertical = 3.dp), verticalAlignment = Alignment.CenterVertically) {
                Text(if (step.done) "✓" else "…", color = if (step.done) c.accent else c.text, modifier = Modifier.widthIn(min = 24.dp))
                Text(stepName(step), color = if (step.done) c.muted else c.text, style = MaterialTheme.typography.bodyMedium)
            }
        }
    }
    if (screen.failed != null) {
        Spacer(Modifier.height(12.dp))
        Text(stringResource(R.string.ms_failed), color = c.err, style = MaterialTheme.typography.titleSmall)
        Spacer(Modifier.height(4.dp))
        Text(screen.failed, color = c.err, style = MaterialTheme.typography.bodyMedium)
        Spacer(Modifier.height(4.dp))
        Small(stringResource(R.string.pair_failed_note))
        Spacer(Modifier.height(16.dp))
        PrimaryButton(stringResource(R.string.pair_back), model::back, Modifier.fillMaxWidth())
    } else {
        if (screen.detail.isNotEmpty()) {
            Spacer(Modifier.height(10.dp))
            Small(screen.detail)
        }
        Spacer(Modifier.height(10.dp))
        Small(stringResource(R.string.ms_progress_wait))
    }
}

// ----------------------------------------------------------------- result

@Composable
private fun PairResultPage(model: PairModel, screen: MsScreen.PairResult) {
    screen.notes.forEach {
        Body(it)
        Spacer(Modifier.height(6.dp))
    }
    Spacer(Modifier.height(8.dp))
    PairConfigBlock(model, screen.pairId)
    Spacer(Modifier.height(16.dp))
    PrimaryButton(stringResource(R.string.pair_use_in_app), { model.useInApp(screen.pairId) }, Modifier.fillMaxWidth())
}

@Composable
private fun PairConfigBlock(model: PairModel, pairId: String) {
    val c = ZeroTheme.colors
    model.configs(pairId).forEach { cfg ->
        ZeroCard(Modifier.fillMaxWidth().padding(bottom = 8.dp)) {
            Text(cfg.service, style = MaterialTheme.typography.labelLarge, color = c.text)
            cfg.link?.let { link ->
                Spacer(Modifier.height(8.dp))
                QrCode(link, cfg.service)
                Spacer(Modifier.height(8.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    TonalButton(stringResource(R.string.ms_copy), { model.copy(link, true) })
                    TonalButton(stringResource(R.string.ms_share), { model.startIntent(android.content.Intent(android.content.Intent.ACTION_SEND).apply { type = "text/plain"; putExtra(android.content.Intent.EXTRA_TEXT, link) }) })
                }
            }
        }
    }
}

// ------------------------------------------------------------------ server

@Composable
private fun PairServerPage(model: PairModel, screen: MsScreen.PairServer) {
    val pair = model.pair(screen.pairId) ?: return
    LaunchedEffect(screen.pairId) {
        model.refreshPairUsage(screen.pairId)
        model.refreshTunnel(screen.pairId)
        model.watchPair(screen.pairId)
    }
    val c = ZeroTheme.colors
    val t = model.tunnel[screen.pairId]
    ZeroCard(Modifier.fillMaxWidth()) {
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text(
                    if (t?.up == true) stringResource(R.string.pair_tunnel_up) else stringResource(R.string.pair_tunnel_down),
                    style = MaterialTheme.typography.titleSmall,
                    color = if (t?.up == true) c.accent else c.err,
                )
                t?.lastHandshakeSecsAgo?.let {
                    Small(stringResource(R.string.pair_handshake, android.text.format.DateUtils.getRelativeTimeSpanString(System.currentTimeMillis() - it * 1000, System.currentTimeMillis(), 0)))
                }
                t?.error?.let { Small(it) }
            }
            TonalButton(stringResource(R.string.pair_relink), { model.relink(screen.pairId) })
        }
    }
    Spacer(Modifier.height(12.dp))
    val usage = model.usage[screen.pairId]
    PairUsageBlock(stringResource(R.string.pair_gateway), pair.record.optJSONObject("gateway")?.optString("host").orEmpty(), usage?.gateway)
    Spacer(Modifier.height(8.dp))
    PairUsageBlock(stringResource(R.string.pair_exit), pair.record.optJSONObject("exit")?.optString("host").orEmpty(), usage?.exit)
    Spacer(Modifier.height(12.dp))
    PairConfigBlock(model, screen.pairId)
    Spacer(Modifier.height(16.dp))
    PrimaryButton(stringResource(R.string.pair_use_in_app), { model.useInApp(screen.pairId) }, Modifier.fillMaxWidth())
    admin?.let {
        Spacer(Modifier.height(8.dp))
        TonalButton(stringResource(R.string.pair_manage), { it.open(screen.pairId) }, Modifier.fillMaxWidth())
    }
    Spacer(Modifier.height(8.dp))
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        TonalButton(stringResource(R.string.pair_remove), { model.askRemovePair(screen.pairId) }, Modifier.weight(1f))
        TonalButton(stringResource(R.string.pair_forget), { model.forgetPair(screen.pairId) }, Modifier.weight(1f))
    }
}

@Composable
private fun PairUsageBlock(title: String, host: String, usage: UsageView?) {
    val c = ZeroTheme.colors
    val context = LocalContext.current
    ZeroCard(Modifier.fillMaxWidth()) {
        Text(title, style = MaterialTheme.typography.labelLarge, color = c.text)
        Small(host)
        Spacer(Modifier.height(6.dp))
        if (usage == null) {
            Small(stringResource(R.string.ms_reading))
        } else {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                val now = usage.inbounds.sumOf { it.now }
                val recent = usage.inbounds.sumOf { it.recent }
                val sessions = usage.inbounds.sumOf { it.sessions }
                Stat2(stringResource(R.string.ms_stat_now), now.toString(), strong = true)
                Stat2(stringResource(R.string.ms_stat_recent, (usage.windowSecs / 60).toInt()), recent.toString())
                Stat2(stringResource(R.string.ms_stat_sessions), sessions.toString())
            }
            Spacer(Modifier.height(6.dp))
            Small(
                stringResource(
                    R.string.ms_traffic,
                    android.text.format.Formatter.formatShortFileSize(context, usage.inbounds.sumOf { it.up }),
                    android.text.format.Formatter.formatShortFileSize(context, usage.inbounds.sumOf { it.down }),
                ),
            )
        }
    }
}

@Composable
private fun Stat2(label: String, value: String, strong: Boolean = false) {
    Column {
        Text(
            value,
            style = MaterialTheme.typography.titleLarge,
            color = if (strong) ZeroTheme.colors.accent else ZeroTheme.colors.text,
        )
        Small(label)
    }
}

@Composable
private fun ConfirmRemovePairPage(model: PairModel, screen: MsScreen.ConfirmRemovePair) {
    Body(stringResource(R.string.pair_confirm_remove))
    Spacer(Modifier.height(20.dp))
    PrimaryButton(stringResource(R.string.pair_yes_remove), { model.removePair(screen.pairId) }, Modifier.fillMaxWidth())
    Spacer(Modifier.height(8.dp))
    TonalButton(stringResource(R.string.ms_cancel), model::back, Modifier.fillMaxWidth())
}
