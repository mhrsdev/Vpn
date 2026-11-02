package com.zeronet.mobile.ui.admin

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.text.selection.SelectionContainer
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
import androidx.compose.ui.unit.dp
import com.zeronet.mobile.R
import com.zeronet.mobile.ui.components.PrimaryButton
import com.zeronet.mobile.ui.components.ToggleRow
import com.zeronet.mobile.ui.components.TonalButton
import com.zeronet.mobile.ui.components.ZeroCard
import com.zeronet.mobile.ui.components.ZeroTextField
import com.zeronet.mobile.ui.theme.ZeroTheme

/**
 * The Huawei router section: the H158-381 5G CPE as an L2TP VPN client, so
 * the whole home network rides the tunnel with no extra hardware (Design G).
 *
 * What the firmware accepts is CONFIRMED by the research (Huawei doc
 * en-us00761349): VPN client with L2TP + PPTP only. PPTP is refused on
 * principle — shown only as an explained absence, never as a choice. Plain
 * L2TP is WEAK: the panel mandates an explicit informed-consent checkbox
 * before any credential is displayed, and never calls the modem link
 * "secure" unqualified.
 *
 * The app never talks to the modem's LAN and hardcodes no values: the
 * backend declares capabilities, owns the modem accounts (chap-secrets),
 * and publishes the step-by-step guide. Until the backend publishes, every
 * block shows an honest empty state instead of guesses.
 */
@Composable
fun HuaweiRouterSection(model: AdminModel) {
    val c = ZeroTheme.colors
    SectionTitle(stringResource(R.string.hw_title))
    val caps = model.modemCaps
    if (caps == null) {
        if (!model.loading) {
            Text(
                stringResource(R.string.hw_no_caps),
                style = MaterialTheme.typography.bodyMedium,
                color = c.muted,
            )
            Spacer(Modifier.height(8.dp))
            TonalButton(stringResource(R.string.admin_refresh), model::refreshRouterCaps, Modifier.fillMaxWidth())
        }
        return
    }

    Text(
        caps.model + (caps.firmware?.let { " · $it" } ?: ""),
        style = MaterialTheme.typography.titleSmall,
        color = c.text,
        modifier = Modifier.semantics { heading() },
    )
    caps.note?.let {
        Spacer(Modifier.height(4.dp))
        Text(it, style = MaterialTheme.typography.bodySmall, color = c.muted)
    }
    Spacer(Modifier.height(12.dp))

    // Protocol support — the honest table, right at the top.
    SectionTitle(stringResource(R.string.hw_protocols))
    caps.vpnClientProtocols.forEach { p ->
        val sec = RouterApi.protocolSecurity(p)
        Spacer(Modifier.height(4.dp))
        SecurityGradeBanner(sec)
    }
    Spacer(Modifier.height(12.dp))

    // Informed consent (Design G §d): explicit, per-session, before any credential.
    SectionTitle(stringResource(R.string.hw_consent_title))
    ZeroCard(Modifier.fillMaxWidth()) {
        ToggleRow(
            title = stringResource(R.string.hw_consent),
            checked = model.modemConsent,
            onCheckedChange = { model.modemConsent = it },
        )
        Spacer(Modifier.height(4.dp))
        Text(
            stringResource(R.string.hw_consent_detail),
            style = MaterialTheme.typography.bodySmall,
            color = c.muted,
        )
    }
    Spacer(Modifier.height(12.dp))

    // Modem accounts.
    SectionTitle(stringResource(R.string.hw_accounts))
    if (model.modemAccounts.isEmpty() && !model.loading) {
        Text(stringResource(R.string.hw_no_accounts), style = MaterialTheme.typography.bodyMedium, color = c.muted)
        Spacer(Modifier.height(8.dp))
    }
    model.modemAccounts.forEach { acc ->
        ModemAccountCard(model, acc)
        Spacer(Modifier.height(8.dp))
    }
    var newName by remember { mutableStateOf("") }
    ZeroCard(Modifier.fillMaxWidth()) {
        Text(stringResource(R.string.hw_new_account), style = MaterialTheme.typography.labelLarge, color = c.text)
        Spacer(Modifier.height(8.dp))
        ZeroTextField(newName, { newName = it }, placeholder = stringResource(R.string.hw_account_name_hint))
        Spacer(Modifier.height(8.dp))
        PrimaryButton(
            stringResource(R.string.hw_create),
            { model.createModemAccount(newName); newName = "" },
            Modifier.fillMaxWidth(),
            enabled = newName.isNotBlank() && model.modemConsent,
        )
        if (!model.modemConsent) {
            Spacer(Modifier.height(4.dp))
            Text(stringResource(R.string.hw_consent_required), style = MaterialTheme.typography.bodySmall, color = c.warn)
        }
    }

    // Credentials: ordered like the modem's form, copy button per value.
    if (model.modemCredentials.isNotEmpty()) {
        Spacer(Modifier.height(12.dp))
        CredentialList(model)
    }

    // Step-by-step guide for the modem's own UI (backend-published, Design G §f).
    Spacer(Modifier.height(12.dp))
    SectionTitle(stringResource(R.string.hw_guide))
    TonalButton(
        stringResource(R.string.hw_load_guide),
        { model.refreshGuide("l2tp") },
        Modifier.fillMaxWidth(),
    )
    Spacer(Modifier.height(8.dp))
    if (model.guideSteps.isEmpty()) {
        Text(stringResource(R.string.hw_no_guide), style = MaterialTheme.typography.bodySmall, color = c.muted)
    } else {
        model.guideSteps.forEachIndexed { i, step ->
            ZeroCard(Modifier.fillMaxWidth().padding(bottom = 8.dp)) {
                Text(
                    "${i + 1}. ${step.title}",
                    style = MaterialTheme.typography.labelLarge,
                    color = c.text,
                    modifier = Modifier.semantics { heading() },
                )
                if (step.body.isNotEmpty()) {
                    Spacer(Modifier.height(4.dp))
                    Text(step.body, style = MaterialTheme.typography.bodyMedium, color = c.text)
                }
            }
        }
    }

    // Security status: the backend's findings, severities never upgraded.
    Spacer(Modifier.height(12.dp))
    SectionTitle(stringResource(R.string.hw_security))
    TonalButton(
        stringResource(R.string.hw_check_security),
        { model.refreshRouterSecurity("l2tp") },
        Modifier.fillMaxWidth(),
    )
    Spacer(Modifier.height(8.dp))
    if (model.securityFindings.isEmpty()) {
        Text(stringResource(R.string.hw_no_findings), style = MaterialTheme.typography.bodySmall, color = c.muted)
    } else {
        model.securityFindings.forEach { f ->
            val color = when (f.severity) {
                "insecure" -> c.err
                "untrustworthy" -> c.warn
                "warning" -> c.warn
                else -> c.accent
            }
            ZeroCard(Modifier.fillMaxWidth().padding(bottom = 8.dp)) {
                Text(f.title, style = MaterialTheme.typography.labelLarge, color = color)
                if (f.detail.isNotEmpty()) {
                    Spacer(Modifier.height(4.dp))
                    Text(f.detail, style = MaterialTheme.typography.bodySmall, color = c.muted)
                }
            }
        }
    }

    // Honest limitations (Design G §h): the panel discloses, never implies otherwise.
    Spacer(Modifier.height(12.dp))
    SectionTitle(stringResource(R.string.hw_limits))
    ZeroCard(Modifier.fillMaxWidth()) {
        listOf(
            R.string.hw_limit_killswitch,
            R.string.hw_limit_crypto,
            R.string.hw_limit_fulltunnel,
            R.string.hw_limit_ipv6,
            R.string.hw_limit_speed,
            R.string.hw_limit_single,
            R.string.hw_limit_dns,
            R.string.hw_limit_firmware,
            R.string.hw_limit_remote,
        ).forEach { res ->
            Text("• " + stringResource(res), style = MaterialTheme.typography.bodySmall, color = c.muted)
            Spacer(Modifier.height(6.dp))
        }
    }
}

@Composable
private fun SectionTitle(text: String) {
    Text(text, style = MaterialTheme.typography.titleSmall, color = ZeroTheme.colors.text, modifier = Modifier.semantics { heading() })
    Spacer(Modifier.height(8.dp))
}

@Composable
private fun ModemAccountCard(model: AdminModel, acc: RouterApi.ModemAccount) {
    val c = ZeroTheme.colors
    val (statusLabel, statusColor) = when (acc.status) {
        "connected" -> stringResource(R.string.hw_status_connected) to c.accent
        "last_seen" -> stringResource(R.string.hw_status_last_seen, acc.lastSeen ?: "—") to c.warn
        else -> stringResource(R.string.hw_status_never) to c.muted
    }
    ZeroCard(Modifier.fillMaxWidth()) {
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text(acc.name, style = MaterialTheme.typography.labelLarge, color = c.text)
                Text(acc.username, style = MaterialTheme.typography.bodySmall, color = c.muted)
                Spacer(Modifier.height(2.dp))
                Text(statusLabel, style = MaterialTheme.typography.bodySmall, color = statusColor)
                Text(
                    stringResource(R.string.hw_data_used, RouterApi.formatBytes(acc.dataUsed)),
                    style = MaterialTheme.typography.bodySmall,
                    color = c.muted,
                )
            }
        }
        Spacer(Modifier.height(8.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            TonalButton(
                stringResource(R.string.hw_show_creds),
                { model.revealModemCredentials(acc) },
                Modifier.weight(1f),
                enabled = model.modemConsent,
            )
            TonalButton(
                stringResource(R.string.hw_rotate),
                { model.rotateModemPassword(acc) },
                Modifier.weight(1f),
                enabled = model.modemConsent,
            )
        }
        Spacer(Modifier.height(8.dp))
        TonalButton(
            stringResource(R.string.hw_revoke),
            { model.revokeModemAccount(acc) },
            Modifier.fillMaxWidth(),
        )
    }
}

@Composable
private fun CredentialList(model: AdminModel) {
    val c = ZeroTheme.colors
    var revealed by remember { mutableStateOf(setOf<String>()) }
    SectionTitle(
        stringResource(R.string.hw_credentials) +
            (model.selectedModemAccount?.let { " — ${it.name}" } ?: ""),
    )
    val grade = RouterApi.protocolSecurity(model.modemCredProtocol.orEmpty())
    SecurityGradeBanner(grade)
    Spacer(Modifier.height(8.dp))
    model.modemCredentials.forEach { cred ->
        val isRevealed = revealed.contains(cred.fieldId)
        val showValue = !cred.sensitive || isRevealed
        ZeroCard(Modifier.fillMaxWidth().padding(bottom = 8.dp)) {
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text(cred.label, style = MaterialTheme.typography.labelMedium, color = c.muted)
                    Spacer(Modifier.height(2.dp))
                    SelectionContainer {
                        Text(
                            if (showValue) cred.value.ifEmpty { "—" } else "••••••••",
                            style = MaterialTheme.typography.bodyLarge,
                            color = c.text,
                        )
                    }
                }
                Column(horizontalAlignment = Alignment.End) {
                    if (cred.sensitive) {
                        TonalButton(
                            stringResource(if (isRevealed) R.string.hw_hide else R.string.hw_reveal),
                            {
                                revealed = if (isRevealed) revealed - cred.fieldId else revealed + cred.fieldId
                            },
                        )
                        Spacer(Modifier.height(4.dp))
                    }
                    TonalButton(stringResource(R.string.ms_copy), { model.copy(cred.value, cred.sensitive) })
                }
            }
        }
    }
    TonalButton(stringResource(R.string.admin_dismiss), model::clearModemCredentials, Modifier.fillMaxWidth())
}

/**
 * The honest grade banner. PPTP renders as refused (never a choice); L2TP
 * renders as WEAK — this composable has no path that renders the modem link
 * as secure unqualified.
 */
@Composable
private fun SecurityGradeBanner(grade: RouterApi.ProtocolSecurity) {
    val c = ZeroTheme.colors
    val color = when (grade.grade) {
        RouterApi.SecurityGrade.REFUSED -> c.err
        RouterApi.SecurityGrade.WEAK -> c.warn
        RouterApi.SecurityGrade.UNTRUSTWORTHY -> c.warn
        RouterApi.SecurityGrade.NOT_AVAILABLE -> c.muted
        RouterApi.SecurityGrade.OK -> c.accent
    }
    ZeroCard(Modifier.fillMaxWidth()) {
        Text(
            "${grade.protocol.uppercase()} — ${grade.label}",
            style = MaterialTheme.typography.labelLarge,
            color = color,
        )
        Spacer(Modifier.height(4.dp))
        Text(grade.detail, style = MaterialTheme.typography.bodySmall, color = c.muted)
    }
}
