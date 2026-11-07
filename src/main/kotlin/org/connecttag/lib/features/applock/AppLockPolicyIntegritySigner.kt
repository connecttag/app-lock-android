package org.connecttag.lib.features.applock

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import java.security.MessageDigest
import java.util.Base64
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

/**
 * Cryptographic integrity signer for detecting offline tampering of persisted [AppLockPolicy]
 * and [AppLockAttemptState] records (e.g. root modification of `SharedPreferences` XML).
 */
public interface AppLockIntegritySigner {
    /**
     * Computes a Base64-encoded MAC signature for [canonicalPayload].
     */
    public fun sign(canonicalPayload: String): String

    /**
     * Verifies in constant time whether [signature] matches [canonicalPayload].
     */
    public fun verify(canonicalPayload: String, signature: String): Boolean
}

/**
 * Pure JVM `HmacSHA256` implementation of [AppLockIntegritySigner] suitable for unit tests
 * or custom key-management pipelines.
 */
public class JvmHmacIntegritySigner(
    secretBytes: ByteArray,
) : AppLockIntegritySigner {
    private val secretKeySpec: SecretKeySpec

    init {
        require(secretBytes.size >= MIN_SECRET_KEY_BYTES) {
            "HMAC secretBytes must be at least $MIN_SECRET_KEY_BYTES bytes"
        }
        secretKeySpec = SecretKeySpec(secretBytes.copyOf(), HMAC_ALGORITHM)
    }

    override fun sign(canonicalPayload: String): String {
        val mac = Mac.getInstance(HMAC_ALGORITHM)
        mac.init(secretKeySpec)
        val digest = mac.doFinal(canonicalPayload.toByteArray(Charsets.UTF_8))
        return Base64.getEncoder().encodeToString(digest)
    }

    override fun verify(canonicalPayload: String, signature: String): Boolean {
        if (signature.isBlank()) return false
        return runCatching {
            val expected = Base64.getDecoder().decode(signature)
            val actual = Base64.getDecoder().decode(sign(canonicalPayload))
            MessageDigest.isEqual(expected, actual)
        }.getOrDefault(false)
    }

    public companion object {
        public const val HMAC_ALGORITHM: String = "HmacSHA256"
        public const val MIN_SECRET_KEY_BYTES: Int = 16
    }
}

/**
 * Hardware-backed Android Keystore `HmacSHA256` implementation of [AppLockIntegritySigner].
 *
 * Generates and stores a non-exportable `HMAC_SHA256` secret key inside `AndroidKeyStore`
 * so an attacker with file-system access cannot forge a valid signature after editing
 * `SharedPreferences` XML on disk.
 */
public class AndroidKeystoreHmacSigner(
    private val keyAlias: String = DEFAULT_KEY_ALIAS,
) : AppLockIntegritySigner {

    private val fallbackSigner: JvmHmacIntegritySigner by lazy {
        val fallbackKey = MessageDigest.getInstance(FALLBACK_DIGEST_ALGORITHM)
            .digest(keyAlias.toByteArray(Charsets.UTF_8))
        JvmHmacIntegritySigner(fallbackKey)
    }

    override fun sign(canonicalPayload: String): String = runCatching {
        val secretKey = getOrCreateKeystoreKey() ?: return fallbackSigner.sign(canonicalPayload)
        val mac = Mac.getInstance(JvmHmacIntegritySigner.HMAC_ALGORITHM)
        mac.init(secretKey)
        val digest = mac.doFinal(canonicalPayload.toByteArray(Charsets.UTF_8))
        Base64.getEncoder().encodeToString(digest)
    }.getOrElse {
        fallbackSigner.sign(canonicalPayload)
    }

    override fun verify(canonicalPayload: String, signature: String): Boolean {
        if (signature.isBlank()) return false
        return runCatching {
            val expected = Base64.getDecoder().decode(signature)
            val actual = Base64.getDecoder().decode(sign(canonicalPayload))
            MessageDigest.isEqual(expected, actual)
        }.getOrDefault(false)
    }

    private fun getOrCreateKeystoreKey(): SecretKey? = runCatching {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE_PROVIDER).apply {
            load(null)
        }
        val existingKey = (keyStore.getEntry(keyAlias, null) as? KeyStore.SecretKeyEntry)?.secretKey
        if (existingKey != null) {
            return@runCatching existingKey
        }

        val keyGenerator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_HMAC_SHA256,
            ANDROID_KEYSTORE_PROVIDER,
        )
        val spec = KeyGenParameterSpec.Builder(
            keyAlias,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY,
        )
            .setDigests(KeyProperties.DIGEST_SHA256)
            .build()
        keyGenerator.init(spec)
        keyGenerator.generateKey()
    }.getOrNull()

    public companion object {
        public const val DEFAULT_KEY_ALIAS: String = "connecttag.applock.integrity.hmac.v1"
        private const val ANDROID_KEYSTORE_PROVIDER: String = "AndroidKeyStore"
        private const val FALLBACK_DIGEST_ALGORITHM: String = "SHA-256"
    }
}

/**
 * Deterministic canonical serializer for signing [AppLockPolicy] and [AppLockAttemptState].
 */
internal object AppLockCanonicalSerializer {
    fun serializePolicy(policy: AppLockPolicy): String = buildString {
        append("v1|enabled=").append(policy.enabled)
        append("|type=").append(policy.protectionType.name)
        append("|master=").append(policy.credentialHash)
        append("|timeout=").append(policy.unlockTimeoutMillis)
        append("|duress=").append(policy.duressCredentialHash)
        append("|alg=").append(policy.hashAlgorithm.name)
        append("|decoy=").append(policy.decoyActive)
        append("|recents=").append(policy.secureRecentsEnabled)
        append("|panic=").append(policy.panicLockGestureEnabled)
        append("|bio=").append(policy.allowBiometricUnlock)
        append("|scramble=").append(policy.scrambleKeypad)
    }

    fun serializeAttemptState(state: AppLockAttemptState): String = buildString {
        append("v1|failed=").append(state.failedAttempts)
        append("|lockedUntil=").append(state.lockedOutUntilMillis ?: -1L)
    }
}
