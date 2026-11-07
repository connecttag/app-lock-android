package org.connecttag.lib.features.applock

import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Storage contract for persisting [AppLockPolicy], unlock timestamps, and attempt lockout state.
 */
public interface AppLockStateStore {
    public fun readPolicy(): AppLockPolicy
    public fun writePolicy(policy: AppLockPolicy)
    public fun readLastUnlockTimestampMillis(): Long
    public fun writeLastUnlockTimestampMillis(timestampMillis: Long)

    /**
     * Reads persisted failed attempt state so process death cannot bypass active cooldown lockouts.
     */
    public fun readAttemptState(): AppLockAttemptState = AppLockAttemptState()

    /**
     * Persists failed attempt and lockout deadline state.
     */
    public fun writeAttemptState(state: AppLockAttemptState) {}

    /**
     * Returns `true` if persisted security records pass cryptographic integrity verification,
     * or `false` if offline tampering of policy/lockout records was detected.
     */
    public fun isIntegrityValid(): Boolean = true

    /**
     * Clears all stored credentials and resets the policy to [AppLockPolicy].
     */
    public fun clear() {
        writePolicy(AppLockPolicy())
        writeLastUnlockTimestampMillis(0L)
        writeAttemptState(AppLockAttemptState())
    }
}

/**
 * Extension of [AppLockStateStore] exposing a reactive [Flow] of [AppLockPolicy] updates.
 */
public interface ReactiveAppLockStateStore : AppLockStateStore {
    public val policyFlow: StateFlow<AppLockPolicy>
}

/**
 * Thread-safe in-memory implementation of [ReactiveAppLockStateStore] for testing, previews,
 * or ephemeral sessions.
 */
public class InMemoryAppLockStateStore(
    initialPolicy: AppLockPolicy = AppLockPolicy(),
    initialLastUnlockTimestampMillis: Long = 0L,
    initialAttemptState: AppLockAttemptState = AppLockAttemptState(),
) : ReactiveAppLockStateStore {
    private val mutablePolicyFlow: MutableStateFlow<AppLockPolicy> = MutableStateFlow(initialPolicy)

    @Volatile
    private var lastUnlockMillis: Long = initialLastUnlockTimestampMillis

    @Volatile
    private var attemptState: AppLockAttemptState = initialAttemptState

    @Volatile
    private var integrityValid: Boolean = true

    override val policyFlow: StateFlow<AppLockPolicy> = mutablePolicyFlow.asStateFlow()

    override fun readPolicy(): AppLockPolicy = mutablePolicyFlow.value

    override fun writePolicy(policy: AppLockPolicy) {
        mutablePolicyFlow.value = policy
        integrityValid = true
    }

    override fun readLastUnlockTimestampMillis(): Long = lastUnlockMillis

    override fun writeLastUnlockTimestampMillis(timestampMillis: Long) {
        lastUnlockMillis = timestampMillis
    }

    override fun readAttemptState(): AppLockAttemptState = attemptState

    override fun writeAttemptState(state: AppLockAttemptState) {
        attemptState = state
    }

    override fun isIntegrityValid(): Boolean = integrityValid

    /**
     * Simulates an offline tamper condition for security unit testing.
     */
    public fun simulateTamperDetected(tampered: Boolean = true) {
        integrityValid = !tampered
    }
}
