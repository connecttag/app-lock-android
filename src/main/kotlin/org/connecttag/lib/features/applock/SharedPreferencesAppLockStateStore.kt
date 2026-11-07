package org.connecttag.lib.features.applock

import android.content.Context
import android.content.SharedPreferences
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Default Android [SharedPreferences]-backed implementation of [ReactiveAppLockStateStore]
 * with hardware-backed `HmacSHA256` integrity verification ([AppLockIntegritySigner]) to detect
 * and fail-close against offline XML tampering.
 */
public class SharedPreferencesAppLockStateStore(
    context: Context,
    preferencesName: String = DEFAULT_PREFERENCES_NAME,
    private val integritySigner: AppLockIntegritySigner = AndroidKeystoreHmacSigner(),
) : ReactiveAppLockStateStore {
    private val preferences: SharedPreferences = context.applicationContext.getSharedPreferences(
        preferencesName,
        Context.MODE_PRIVATE,
    )

    @Volatile
    private var lastIntegrityCheckValid: Boolean = true

    private val mutablePolicyFlow: MutableStateFlow<AppLockPolicy> = MutableStateFlow(loadPolicyFromPrefs())

    override val policyFlow: StateFlow<AppLockPolicy> = mutablePolicyFlow.asStateFlow()

    override fun readPolicy(): AppLockPolicy = loadPolicyFromPrefs().also { latest ->
        mutablePolicyFlow.value = latest
    }

    override fun writePolicy(policy: AppLockPolicy) {
        val signature = integritySigner.sign(AppLockCanonicalSerializer.serializePolicy(policy))
        preferences.edit()
            .putBoolean(KEY_ENABLED, policy.enabled)
            .putString(KEY_PROTECTION_TYPE, policy.protectionType.name)
            .putString(KEY_CREDENTIAL_HASH, policy.credentialHash)
            .putLong(KEY_UNLOCK_TIMEOUT, policy.unlockTimeoutMillis)
            .putString(KEY_DURESS_CREDENTIAL_HASH, policy.duressCredentialHash)
            .putString(KEY_HASH_ALGORITHM, policy.hashAlgorithm.name)
            .putBoolean(KEY_DECOY_ACTIVE, policy.decoyActive)
            .putBoolean(KEY_SECURE_RECENTS, policy.secureRecentsEnabled)
            .putBoolean(KEY_PANIC_GESTURE, policy.panicLockGestureEnabled)
            .putBoolean(KEY_ALLOW_BIOMETRIC, policy.allowBiometricUnlock)
            .putBoolean(KEY_SCRAMBLE_KEYPAD, policy.scrambleKeypad)
            .putString(KEY_POLICY_SIGNATURE, signature)
            .apply()
        lastIntegrityCheckValid = true
        mutablePolicyFlow.value = policy
    }

    override fun readLastUnlockTimestampMillis(): Long = preferences.getLong(KEY_LAST_UNLOCK, 0L)

    override fun writeLastUnlockTimestampMillis(timestampMillis: Long) {
        preferences.edit().putLong(KEY_LAST_UNLOCK, timestampMillis).apply()
    }

    override fun readAttemptState(): AppLockAttemptState {
        val failedAttempts = preferences.getInt(KEY_FAILED_ATTEMPTS, 0)
        val lockedUntil = preferences.getLong(KEY_LOCKED_OUT_UNTIL, NO_LOCKOUT_VALUE)
        val state = AppLockAttemptState(
            failedAttempts = failedAttempts,
            lockedOutUntilMillis = lockedUntil.takeIf { it > 0L },
        )
        val storedSignature = preferences.getString(KEY_ATTEMPT_SIGNATURE, null)
        if (storedSignature != null) {
            val valid = integritySigner.verify(
                canonicalPayload = AppLockCanonicalSerializer.serializeAttemptState(state),
                signature = storedSignature,
            )
            if (!valid) {
                lastIntegrityCheckValid = false
            }
        }
        return state
    }

    override fun writeAttemptState(state: AppLockAttemptState) {
        val signature = integritySigner.sign(AppLockCanonicalSerializer.serializeAttemptState(state))
        preferences.edit()
            .putInt(KEY_FAILED_ATTEMPTS, state.failedAttempts)
            .putLong(KEY_LOCKED_OUT_UNTIL, state.lockedOutUntilMillis ?: NO_LOCKOUT_VALUE)
            .putString(KEY_ATTEMPT_SIGNATURE, signature)
            .apply()
    }

    override fun isIntegrityValid(): Boolean = lastIntegrityCheckValid

    private fun loadPolicyFromPrefs(): AppLockPolicy {
        val rawPolicy = AppLockPolicy(
            enabled = preferences.getBoolean(KEY_ENABLED, false),
            protectionType = runCatching {
                AppLockProtectionType.valueOf(
                    preferences.getString(KEY_PROTECTION_TYPE, AppLockProtectionType.NONE.name).orEmpty(),
                )
            }.getOrDefault(AppLockProtectionType.NONE),
            credentialHash = preferences.getString(KEY_CREDENTIAL_HASH, "").orEmpty(),
            unlockTimeoutMillis = preferences.getLong(
                KEY_UNLOCK_TIMEOUT,
                AppLockPolicy.DEFAULT_UNLOCK_TIMEOUT_MILLIS,
            ),
            duressCredentialHash = preferences.getString(KEY_DURESS_CREDENTIAL_HASH, "").orEmpty(),
            hashAlgorithm = runCatching {
                CredentialHashAlgorithm.valueOf(
                    preferences.getString(
                        KEY_HASH_ALGORITHM,
                        CredentialHashAlgorithm.PBKDF2_HMAC_SHA256.name,
                    ).orEmpty(),
                )
            }.getOrDefault(CredentialHashAlgorithm.PBKDF2_HMAC_SHA256),
            decoyActive = preferences.getBoolean(KEY_DECOY_ACTIVE, false),
            secureRecentsEnabled = preferences.getBoolean(KEY_SECURE_RECENTS, true),
            panicLockGestureEnabled = preferences.getBoolean(KEY_PANIC_GESTURE, true),
            allowBiometricUnlock = preferences.getBoolean(KEY_ALLOW_BIOMETRIC, false),
            scrambleKeypad = preferences.getBoolean(KEY_SCRAMBLE_KEYPAD, false),
        )

        val hasAnyPersistedPolicy = preferences.contains(KEY_ENABLED) ||
            preferences.contains(KEY_CREDENTIAL_HASH)
        if (!hasAnyPersistedPolicy) {
            lastIntegrityCheckValid = true
            return rawPolicy
        }

        val storedSignature = preferences.getString(KEY_POLICY_SIGNATURE, null)
        if (storedSignature == null) {
            // Migrate pre-existing unsigned preferences transparently by signing them once.
            val migratedSig = integritySigner.sign(AppLockCanonicalSerializer.serializePolicy(rawPolicy))
            preferences.edit().putString(KEY_POLICY_SIGNATURE, migratedSig).apply()
            lastIntegrityCheckValid = true
            return rawPolicy
        }

        val signatureValid = integritySigner.verify(
            canonicalPayload = AppLockCanonicalSerializer.serializePolicy(rawPolicy),
            signature = storedSignature,
        )
        lastIntegrityCheckValid = signatureValid

        return if (signatureValid) {
            rawPolicy
        } else {
            // Fail-closed if an attacker modified XML (e.g., setting enabled = false).
            rawPolicy.copy(enabled = true)
        }
    }

    public companion object {
        public const val DEFAULT_PREFERENCES_NAME: String = "app_lock"
        private const val KEY_ENABLED: String = "enabled"
        private const val KEY_PROTECTION_TYPE: String = "protection_type"
        private const val KEY_CREDENTIAL_HASH: String = "credential_hash"
        private const val KEY_UNLOCK_TIMEOUT: String = "unlock_timeout"
        private const val KEY_LAST_UNLOCK: String = "last_unlock"
        private const val KEY_DURESS_CREDENTIAL_HASH: String = "duress_credential_hash"
        private const val KEY_HASH_ALGORITHM: String = "hash_algorithm"
        private const val KEY_DECOY_ACTIVE: String = "decoy_active"
        private const val KEY_SECURE_RECENTS: String = "secure_recents"
        private const val KEY_PANIC_GESTURE: String = "panic_gesture"
        private const val KEY_ALLOW_BIOMETRIC: String = "allow_biometric"
        private const val KEY_SCRAMBLE_KEYPAD: String = "scramble_keypad"
        private const val KEY_POLICY_SIGNATURE: String = "policy_hmac_sig"
        private const val KEY_FAILED_ATTEMPTS: String = "failed_attempts"
        private const val KEY_LOCKED_OUT_UNTIL: String = "locked_out_until"
        private const val KEY_ATTEMPT_SIGNATURE: String = "attempt_hmac_sig"
        private const val NO_LOCKOUT_VALUE: Long = -1L
    }
}
