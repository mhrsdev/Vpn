package com.zeronet.mobile.data

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Symmetric encryption for the private store file.
 *
 * The production implementation is [KeystoreCipher] (AES-256-GCM, key in
 * Android Keystore, never leaves the device). The interface is injectable so
 * unit tests can use a deterministic JVM cipher instead of the Android
 * Keystore, which does not exist on the JVM.
 */
interface StoreCipher {
    /** False on platforms without the backing (JVM tests): the store degrades to plaintext, honestly. */
    val available: Boolean

    /** Returns `iv || ciphertext` (IV is 12 random bytes, prepended). */
    fun encrypt(plain: ByteArray): ByteArray

    /** Inverse of [encrypt]. */
    fun decrypt(blob: ByteArray): ByteArray
}

/**
 * AES-256-GCM with the key held by Android Keystore.
 *
 * `setUserAuthenticationRequired(false)`: the phone reconnects in the
 * background (boot, network flips) without the user present, so unattended
 * decryption is required. Key access is still gated by the app UID and the
 * hardware/TEE backing when the device has one.
 */
class KeystoreCipher(private val alias: String = DEFAULT_ALIAS) : StoreCipher {

    override val available: Boolean
        get() = runCatching { KeyStore.getInstance("AndroidKeyStore") }.isSuccess

    private val key: SecretKey by lazy {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (ks.getEntry(alias, null) as? KeyStore.SecretKeyEntry)?.secretKey ?: run {
            val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setUserAuthenticationRequired(false)
                .setRandomizedEncryptionRequired(true)
                .build()
            KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").apply {
                init(spec)
            }.generateKey()
        }
    }

    override fun encrypt(plain: ByteArray): ByteArray {
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, key)
        val iv = c.iv
        require(iv.size == IV_BYTES) { "unexpected GCM IV length ${iv.size}" }
        return iv + c.doFinal(plain)
    }

    override fun decrypt(blob: ByteArray): ByteArray {
        require(blob.size > IV_BYTES)
        val iv = blob.copyOfRange(0, IV_BYTES)
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(TAG_BITS, iv))
        return c.doFinal(blob.copyOfRange(IV_BYTES, blob.size))
    }

    companion object {
        const val DEFAULT_ALIAS = "zray-store-key"
        private const val IV_BYTES = 12
        private const val TAG_BITS = 128
    }
}

/**
 * AES-256-GCM on the plain JVM (javax.crypto), for unit tests: real
 * encryption, deterministic key, no Android Keystore involved.
 */
class JvmAesGcmCipher(keyBytes: ByteArray) : StoreCipher {
    private val key: SecretKey = javax.crypto.spec.SecretKeySpec(keyBytes.copyOf(32), "AES")
    override val available: Boolean = true

    override fun encrypt(plain: ByteArray): ByteArray {
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, key)
        return c.iv + c.doFinal(plain)
    }

    override fun decrypt(blob: ByteArray): ByteArray {
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, blob, 0, 12))
        return c.doFinal(blob, 12, blob.size - 12)
    }
}

/** No-op cipher for tests that only care about the store's file logic. */
object PlainStoreCipher : StoreCipher {
    override val available: Boolean = false
    override fun encrypt(plain: ByteArray): ByteArray = plain
    override fun decrypt(blob: ByteArray): ByteArray = blob
}
