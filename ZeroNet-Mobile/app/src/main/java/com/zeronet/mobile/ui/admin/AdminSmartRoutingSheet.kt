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
import com.zeronet.mobile.ui.components.TonalButton
import com.zeronet.mobile.ui.components.ToggleRow
import com.zeronet.mobile.ui.components.ZeroCard
import com.zeronet.mobile.ui.components.ZeroChip
import com.zeronet.mobile.ui.components.ZeroTextField
import com.zeronet.mobile.ui.theme.ZeroTheme

/**
 * Smart split-routing: the Iran gateway classifies destinations — Iranian
 * → direct Iran egress, foreign/unknown → USA tunnel (unknown defaults to
 * USA, never to Iran egress or direct).
 *
 * Rules are versioned on the backend; this UI lists, adds, edits, removes
 * and enables/disables them, and tests what a domain or IP would do — the
 * backend's answer is authoritative, with an instant local preview while
 * typing.
 */
@Composable
fun SmartRoutingSection(model: AdminModel) {
    val c = ZeroTheme.colors
    SectionTitle2(stringResource(R.string.sr_title))
    model.rulesVersion?.let {
        Text(
            stringResource(R.string.sr_version, it),
            style = MaterialTheme.typography.bodySmall,
            color = c.muted,
        )
        Spacer(Modifier.height(8.dp))
    }

    // The rule tester first: it is the fastest way to understand the list.
    RuleTester(model)
    Spacer(Modifier.height(16.dp))

    // The rules, in priority order.
    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
        Text(
            stringResource(R.string.sr_rules),
            style = MaterialTheme.typography.titleSmall,
            color = c.text,
            modifier = Modifier.weight(1f).semantics { heading() },
        )
        TonalButton(
            stringResource(R.string.sr_add),
            { model.editingRule = RouterApi.SplitRule("", "domain", "", "iran", nextPriority(model), true, null) },
        )
    }
    Spacer(Modifier.height(8.dp))
    if (model.splitRules.isEmpty() && !model.loading) {
        Text(stringResource(R.string.sr_no_rules), style = MaterialTheme.typography.bodyMedium, color = c.muted)
    }
    model.splitRules.forEach { rule ->
        ZeroCard(Modifier.fillMaxWidth().padding(bottom = 8.dp)) {
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text(rule.value.ifEmpty { "—" }, style = MaterialTheme.typography.labelLarge, color = c.text)
                    Text(
                        "${rule.kind} · ${actionLabel(rule.action)} · #${rule.priority}" +
                            (rule.note?.let { " · $it" } ?: ""),
                        style = MaterialTheme.typography.bodySmall,
                        color = c.muted,
                    )
                }
                Text(
                    if (rule.enabled) stringResource(R.string.admin_enabled) else stringResource(R.string.admin_disabled),
                    color = if (rule.enabled) c.accent else c.err,
                    style = MaterialTheme.typography.labelMedium,
                )
            }
            Spacer(Modifier.height(8.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                TonalButton(stringResource(R.string.sr_edit), { model.editingRule = rule }, Modifier.weight(1f))
                TonalButton(
                    stringResource(if (rule.enabled) R.string.admin_disable else R.string.admin_enable),
                    { model.setRuleEnabled(rule, !rule.enabled) },
                    Modifier.weight(1f),
                )
                TonalButton(stringResource(R.string.admin_delete), { model.deleteSplitRule(rule) }, Modifier.weight(1f))
            }
        }
    }

    // The add/edit form.
    model.editingRule?.let { rule ->
        Spacer(Modifier.height(8.dp))
        RuleForm(model, rule)
    }
}

private fun nextPriority(model: AdminModel): Int =
    (model.splitRules.maxOfOrNull { it.priority } ?: 0) + 10

@Composable
private fun actionLabel(action: String): String = when (action) {
    "iran" -> stringResource(R.string.sr_action_iran)
    "usa" -> stringResource(R.string.sr_action_usa)
    else -> action
}

@Composable
private fun SectionTitle2(text: String) {
    Text(text, style = MaterialTheme.typography.titleSmall, color = ZeroTheme.colors.text, modifier = Modifier.semantics { heading() })
    Spacer(Modifier.height(8.dp))
}

@Composable
private fun RuleForm(model: AdminModel, initial: RouterApi.SplitRule) {
    val c = ZeroTheme.colors
    var kind by remember(initial) { mutableStateOf(initial.kind) }
    var value by remember(initial) { mutableStateOf(initial.value) }
    var action by remember(initial) { mutableStateOf(initial.action) }
    var priority by remember(initial) { mutableStateOf(initial.priority.toString()) }
    var note by remember(initial) { mutableStateOf(initial.note.orEmpty()) }
    ZeroCard(Modifier.fillMaxWidth()) {
        Text(
            if (initial.id.isEmpty()) stringResource(R.string.sr_add) else stringResource(R.string.sr_edit),
            style = MaterialTheme.typography.labelLarge,
            color = c.text,
            modifier = Modifier.semantics { heading() },
        )
        Spacer(Modifier.height(8.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            listOf("domain", "ip", "cidr", "geoip").forEach { k ->
                ZeroChip(k, { kind = k }, selected = kind == k)
            }
        }
        Spacer(Modifier.height(8.dp))
        ZeroTextField(
            value, { value = it },
            placeholder = when (kind) {
                "domain" -> "bank.ir"
                "ip" -> "185.10.10.10"
                "cidr" -> "185.10.10.0/24"
                else -> "IR"
            },
        )
        Spacer(Modifier.height(8.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            ZeroChip(stringResource(R.string.sr_action_iran), { action = "iran" }, selected = action == "iran")
            ZeroChip(stringResource(R.string.sr_action_usa), { action = "usa" }, selected = action == "usa")
        }
        Spacer(Modifier.height(8.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Column(Modifier.weight(1f)) {
                Text(stringResource(R.string.sr_priority), style = MaterialTheme.typography.labelMedium, color = c.muted)
                ZeroTextField(priority, { priority = it.filter(Char::isDigit).take(4) }, keyboardType = KeyboardType.Number)
            }
            Column(Modifier.weight(2f)) {
                Text(stringResource(R.string.sr_note), style = MaterialTheme.typography.labelMedium, color = c.muted)
                ZeroTextField(note, { note = it }, placeholder = stringResource(R.string.sr_note_hint))
            }
        }
        Spacer(Modifier.height(12.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            PrimaryButton(
                stringResource(R.string.action_save),
                {
                    model.saveSplitRule(
                        initial.copy(
                            kind = kind,
                            value = value.trim(),
                            action = action,
                            priority = priority.toIntOrNull() ?: initial.priority,
                            note = note.trim().takeIf { it.isNotEmpty() },
                        ),
                    )
                },
                Modifier.weight(1f),
                enabled = value.isNotBlank(),
            )
            TonalButton(stringResource(R.string.ms_cancel), { model.editingRule = null }, Modifier.weight(1f))
        }
    }
}

@Composable
private fun RuleTester(model: AdminModel) {
    val c = ZeroTheme.colors
    var target by remember { mutableStateOf("") }
    ZeroCard(Modifier.fillMaxWidth()) {
        Text(
            stringResource(R.string.sr_tester),
            style = MaterialTheme.typography.labelLarge,
            color = c.text,
            modifier = Modifier.semantics { heading() },
        )
        Spacer(Modifier.height(8.dp))
        ZeroTextField(
            target,
            {
                target = it
                model.previewRoute(it)
            },
            placeholder = stringResource(R.string.sr_tester_hint),
        )
        // Instant local preview while typing; the backend stays authoritative.
        model.testLocalPreview?.let { preview ->
            Spacer(Modifier.height(4.dp))
            Text(
                stringResource(R.string.sr_preview, actionLabel(preview.route), preview.reason),
                style = MaterialTheme.typography.bodySmall,
                color = c.muted,
            )
        }
        Spacer(Modifier.height(8.dp))
        PrimaryButton(
            stringResource(R.string.sr_test),
            { model.testRoute(target.trim()) },
            Modifier.fillMaxWidth(),
            enabled = target.isNotBlank(),
        )
        model.testResult?.let { r ->
            Spacer(Modifier.height(12.dp))
            val routeColor = when (r.route) {
                "iran" -> c.accent
                "usa" -> c.accent
                else -> c.err
            }
            Text(
                stringResource(R.string.sr_result_route, actionLabel(r.route)),
                style = MaterialTheme.typography.titleSmall,
                color = routeColor,
            )
            Spacer(Modifier.height(4.dp))
            TestRow(stringResource(R.string.sr_result_rule), r.matchedRule?.let { "${it.kind}:${it.value}" } ?: stringResource(R.string.sr_result_default))
            r.exitCountry?.let { TestRow(stringResource(R.string.sr_result_exit), it) }
            r.dnsPolicy?.let { TestRow(stringResource(R.string.sr_result_dns), it) }
            TestRow(stringResource(R.string.sr_result_confidence), "${(r.confidence * 100).toInt()}%")
            if (r.reason.isNotEmpty()) {
                Spacer(Modifier.height(4.dp))
                Text(r.reason, style = MaterialTheme.typography.bodySmall, color = c.muted)
            }
            Spacer(Modifier.height(8.dp))
            TonalButton(stringResource(R.string.admin_dismiss), model::clearTest, Modifier.fillMaxWidth())
        }
    }
}

@Composable
private fun TestRow(label: String, value: String) {
    val c = ZeroTheme.colors
    Row(Modifier.fillMaxWidth().padding(vertical = 2.dp)) {
        Text(label, style = MaterialTheme.typography.bodySmall, color = c.muted, modifier = Modifier.weight(1f))
        Text(value, style = MaterialTheme.typography.bodySmall, color = c.text)
    }
}
