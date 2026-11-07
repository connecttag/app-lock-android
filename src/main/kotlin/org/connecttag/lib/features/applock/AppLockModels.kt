package org.connecttag.lib.features.applock

/**
 * Supported protection mechanisms for application lock.
 */
public enum class AppLockProtectionType {
    NONE,
    PIN,
    PATTERN,
    BIOMETRIC,
    PASSWORD,
}

/**
 * Supported cryptographic digest algorithms for credential storage and verification.
 */
public enum class CredentialHashAlgorithm {
    PBKDF2_HMAC_SHA256,
    SHA_256,
    LEGACY_SHA_1,
}

/**
 * Result of verifying a PIN or credential against the configured Master and Duress policies.
 */
public enum class AppLockUnlockResult {
    /** Matched the primary (Master) credential; unlocks the real application. */
    MASTER,

    /** Matched the secondary (Duress/Camouflage) credential; activates decoy mode without exposing real data. */
    DURESS,

    /** Verification rejected because the attempt tracker is currently in a cooldown lockout window. */
    LOCKED_OUT,

    /** Provided credential did not match any configured secret. */
    INVALID,
}

/**
 * High-level gate mode governing what UI surface is permitted to render.
 *
 * Designed with a strict **Fail-Closed** guarantee: until persistent policy state is loaded
 * without error, the gate remains in [LOADING] and never exposes [UNLOCKED].
 */
public enum class AppLockGateMode {
    /** Security policy is still loading or failed to load; real app content must stay hidden. */
    LOADING,

    /** Application is unlocked and authenticated; real app content may render. */
    UNLOCKED,

    /** Application requires authentication (PIN pad or disguise screen). */
    LOCKED,

    /** Duress credential was entered; decoy/camouflage workspace is active. */
    DECOY,
}

/**
 * Pure fail-closed gate mode resolver extracted from `com.protection.connected` stealth gate logic.
 */
public object AppLockGateResolver {
    /**
     * Resolves the active [AppLockGateMode] from the current policy and session flags.
     *
     * - If [policy] is `null` or [loadFailed] is `true`, always returns [AppLockGateMode.LOADING] (fail-closed).
     * - If [tamperDetected] or [forceLocked] is `true`, returns [AppLockGateMode.LOCKED].
     * - If `policy.enabled && policy.decoyActive`, returns [AppLockGateMode.DECOY] even over a prior session.
     * - If `policy.enabled && !isAuthenticated`, returns [AppLockGateMode.LOCKED].
     * - Otherwise returns [AppLockGateMode.UNLOCKED].
     */
    public fun resolve(
        policy: AppLockPolicy?,
        isAuthenticated: Boolean,
        forceLocked: Boolean = false,
        loadFailed: Boolean = false,
        tamperDetected: Boolean = false,
    ): AppLockGateMode = when {
        policy == null || loadFailed -> AppLockGateMode.LOADING
        tamperDetected || forceLocked -> AppLockGateMode.LOCKED
        policy.enabled && policy.decoyActive -> AppLockGateMode.DECOY
        policy.enabled && !isAuthenticated -> AppLockGateMode.LOCKED
        else -> AppLockGateMode.UNLOCKED
    }
}

/**
 * Persistent application lock policy supporting both standard PIN/Biometric lock
 * and advanced Master + Duress (camouflage/decoy) protection.
 */
public data class AppLockPolicy(
    public val enabled: Boolean = false,
    public val protectionType: AppLockProtectionType = AppLockProtectionType.NONE,
    public val credentialHash: String = "",
    public val unlockTimeoutMillis: Long = DEFAULT_UNLOCK_TIMEOUT_MILLIS,
    public val duressCredentialHash: String = "",
    public val hashAlgorithm: CredentialHashAlgorithm = CredentialHashAlgorithm.PBKDF2_HMAC_SHA256,
    public val decoyActive: Boolean = false,
    public val secureRecentsEnabled: Boolean = true,
    public val panicLockGestureEnabled: Boolean = true,
    public val allowBiometricUnlock: Boolean = false,
    public val scrambleKeypad: Boolean = false,
) {
    /** Returns `true` if a primary (Master) credential hash is configured. */
    public val isMasterCredentialConfigured: Boolean
        get() = credentialHash.isNotBlank()

    /** Returns `true` if a secondary (Duress/Decoy) credential hash is configured. */
    public val isDuressCredentialConfigured: Boolean
        get() = duressCredentialHash.isNotBlank()

    public companion object {
        public const val DEFAULT_UNLOCK_TIMEOUT_MILLIS: Long = 30_000L
    }
}

/**
 * Point-in-time snapshot of the lock manager state.
 */
public data class AppLockSnapshot(
    public val policy: AppLockPolicy,
    public val locked: Boolean,
    public val lastUnlockTimestampMillis: Long,
    public val gateMode: AppLockGateMode = AppLockGateResolver.resolve(
        policy = policy,
        isAuthenticated = !locked,
    ),
    public val attemptState: AppLockAttemptState = AppLockAttemptState(),
    public val tamperDetected: Boolean = false,
)

/**
 * Detailed outcome of a credential verification attempt.
 */
public data class AppLockVerificationOutcome(
    public val result: AppLockUnlockResult,
    public val snapshot: AppLockSnapshot,
) {
    public val isSuccess: Boolean
        get() = result == AppLockUnlockResult.MASTER || result == AppLockUnlockResult.DURESS
}

/**
 * Outcome of configuring or updating Master/Duress PIN credentials.
 */
public sealed interface PinConfigurationResult {
    public data class Success(public val updatedPolicy: AppLockPolicy) : PinConfigurationResult
    public data object CurrentPinInvalid : PinConfigurationResult
    public data class MasterPinInvalid(public val validation: PinValidationStatus) : PinConfigurationResult
    public data class DuressPinInvalid(public val validation: PinValidationStatus) : PinConfigurationResult
    public data object DuplicateMasterAndDuressPin : PinConfigurationResult
}
