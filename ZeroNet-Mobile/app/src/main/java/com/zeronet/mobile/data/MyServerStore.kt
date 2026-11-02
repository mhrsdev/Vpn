package com.zeronet.mobile.data

import android.content.Context
import android.util.Base64
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.security.MessageDigest

/**
 * The servers the person set up from the "My server" page, plus provisioned
 * Iran/USA pairs.
 *
 * A record holds the app's own SSH key for the server (and a pair holds the
 * admin bearer token), so the file is **encrypted** with a key from Android
 * Keystore (see [KeystoreCipher]; audit F W1) on top of living in the app's
 * no-backup directory. The engine process never reads it; the UI hands a
 * record to a request and gets one back.
 *
 * File layout v2: `{"v":2,"encrypted":true,"payload":"<base64 of iv||ciphertext>"}`
 * where the plaintext is `{"entries":[...],"pairs":[...]}`. A v1 file (bare
 * JSON array of entries, plaintext) is migrated in place on the first save.
 * A damaged or undecryptable file reads as empty, never a crash.
 */
class MyServerStore private constructor(context: Context, private val cipher: StoreCipher) {

    private val file = File(context.applicationContext.noBackupFilesDir, FILE_NAME)

    /** One saved server. */
    data class Entry(val record: JSONObject, val configs: JSONArray) {
        val id: String get() = record.optString("id")
        val name: String get() = record.optString("name")
        val host: String get() = record.optString("host")

        /** The services installed, as the core's `kind` words (`reality`, `master_dns`). */
        val kinds: List<String>
            get() = record.optJSONArray("services")?.let { a -> List(a.length()) { a.getJSONObject(it).optString("kind") } }.orEmpty()

        /** The inbound tag each service reports its usage under. */
        fun tagOf(kind: String): String =
            if (kind == "master_dns") "masterdns" else record.optJSONArray("services")?.let { a ->
                (0 until a.length()).map { a.getJSONObject(it) }.firstOrNull { it.optString("kind") == kind }?.optString("tag")
            } ?: kind
    }

    /**
     * One provisioned Iran-gateway/USA-exit pair. [record] is the PairRecord
     * as the core wrote it (opaque here); [adminToken] is the management-API
     * bearer token issued at provision time — encrypted at rest like the SSH
     * keys, passed per-call from memory, never logged.
     */
    data class PairEntry(
        val pairId: String,
        val name: String,
        val record: JSONObject,
        val gatewayConfigs: JSONArray,
        val exitConfigs: JSONArray,
        val tunnel: JSONObject?,
        val adminToken: String?,
    )

    @Synchronized
    fun load(): List<Entry> = loadAll().first

    @Synchronized
    fun pairs(): List<PairEntry> = loadAll().second

    private fun loadAll(): Pair<List<Entry>, List<PairEntry>> {
        val text = runCatching { file.readText() }.getOrNull() ?: return emptyList<Entry>() to emptyList()
        // v1: bare JSON array of entries (plaintext).
        runCatching { JSONArray(text) }.getOrNull()?.let { array ->
            return entriesFrom(array) to emptyList()
        }
        val doc = runCatching { JSONObject(text) }.getOrNull() ?: return emptyList<Entry>() to emptyList()
        if (doc.optInt("v") != 2) return emptyList<Entry>() to emptyList()
        val plain: String = if (doc.optBoolean("encrypted")) {
            if (!cipher.available) return emptyList<Entry>() to emptyList() // key gone or JVM: undecryptable
            val blob = runCatching { Base64.decode(doc.getString("payload"), Base64.DEFAULT) }.getOrNull()
                ?: return emptyList<Entry>() to emptyList()
            runCatching { String(cipher.decrypt(blob), Charsets.UTF_8) }.getOrNull()
                ?: return emptyList<Entry>() to emptyList()
        } else {
            doc.optString("payload")
        }
        val payload = runCatching { JSONObject(plain) }.getOrNull() ?: return emptyList<Entry>() to emptyList()
        return entriesFrom(payload.optJSONArray("entries") ?: JSONArray()) to
            pairsFrom(payload.optJSONArray("pairs") ?: JSONArray())
    }

    private fun entriesFrom(array: JSONArray): List<Entry> =
        (0 until array.length()).mapNotNull { i ->
            runCatching {
                val o = array.getJSONObject(i)
                Entry(o.getJSONObject("record"), o.optJSONArray("configs") ?: JSONArray())
            }.getOrNull()
        }

    private fun pairsFrom(array: JSONArray): List<PairEntry> =
        (0 until array.length()).mapNotNull { i ->
            runCatching {
                val o = array.getJSONObject(i)
                PairEntry(
                    pairId = o.getString("pair_id"),
                    name = o.optString("name"),
                    record = o.getJSONObject("record"),
                    gatewayConfigs = o.optJSONArray("gateway_configs") ?: JSONArray(),
                    exitConfigs = o.optJSONArray("exit_configs") ?: JSONArray(),
                    tunnel = o.optJSONObject("tunnel"),
                    adminToken = o.optString("admin_token").takeIf { it.isNotEmpty() },
                )
            }.getOrNull()
        }

    /** Add [entry], replacing an older one with the same id. */
    @Synchronized
    fun put(entry: Entry) {
        val (entries, pairs) = loadAll()
        save(entries.filter { it.id != entry.id } + entry, pairs)
    }

    @Synchronized
    fun remove(id: String) {
        val (entries, pairs) = loadAll()
        save(entries.filter { it.id != id }, pairs)
    }

    @Synchronized
    fun putPair(pair: PairEntry) {
        val (entries, pairs) = loadAll()
        save(entries, pairs.filter { it.pairId != pair.pairId } + pair)
    }

    @Synchronized
    fun removePair(pairId: String) {
        val (entries, pairs) = loadAll()
        save(entries, pairs.filter { it.pairId != pairId })
    }

    private fun save(entries: List<Entry>, pairs: List<PairEntry>) {
        val payload = JSONObject()
            .put("entries", JSONArray().apply {
                entries.forEach { put(JSONObject().put("record", it.record).put("configs", it.configs)) }
            })
            .put("pairs", JSONArray().apply {
                pairs.forEach {
                    put(JSONObject()
                        .put("pair_id", it.pairId)
                        .put("name", it.name)
                        .put("record", it.record)
                        .put("gateway_configs", it.gatewayConfigs)
                        .put("exit_configs", it.exitConfigs)
                        .put("tunnel", it.tunnel)
                        .put("admin_token", it.adminToken))
                }
            })
        val doc = if (cipher.available) {
            val blob = cipher.encrypt(payload.toString().toByteArray(Charsets.UTF_8))
            JSONObject().put("v", 2).put("encrypted", true)
                .put("payload", Base64.encodeToString(blob, Base64.NO_WRAP))
        } else {
            // JVM / no Keystore: honest plaintext fallback (tests, never a phone).
            JSONObject().put("v", 2).put("encrypted", false).put("payload", payload.toString())
        }
        val temp = File(file.parentFile, "$FILE_NAME.tmp")
        temp.writeText(doc.toString())
        if (!temp.renameTo(file)) {
            file.delete()
            temp.renameTo(file)
        }
    }

    companion object {
        private const val FILE_NAME = "my-servers.json"

        @Volatile private var instance: MyServerStore? = null

        /** Production: Android Keystore encryption. */
        fun get(context: Context): MyServerStore =
            instance ?: synchronized(this) { instance ?: MyServerStore(context, KeystoreCipher()).also { instance = it } }

        /** Tests: injectable cipher (e.g. [JvmAesGcmCipher] or [PlainStoreCipher]). */
        fun get(context: Context, cipher: StoreCipher): MyServerStore =
            instance ?: synchronized(this) { instance ?: MyServerStore(context, cipher).also { instance = it } }

        /**
         * The pair key: 16 hex chars over the two server ids.
         * (Design D names BLAKE3; Kotlin has no BLAKE3, so SHA-256 truncated —
         * same 16-hex spirit, documented here.)
         */
        fun pairIdOf(gatewayId: String, exitId: String): String {
            val digest = MessageDigest.getInstance("SHA-256")
                .digest("$gatewayId:$exitId".toByteArray(Charsets.UTF_8))
            return digest.joinToString("") { "%02x".format(it) }.take(16)
        }
    }
}
