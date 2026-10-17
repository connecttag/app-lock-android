package org.connecttag.features.applock

import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner

public class AppLockManager(
    private val stateStore: AppLockStateStore,
    private val clock: () -> Long = System::currentTimeMillis,
) : DefaultLifecycleObserver {
    @Volatile
    private var locked: Boolean = stateStore.readPolicy().enabled

    @Volatile
    private var shouldEvaluateLockOnResume: Boolean = true

    public fun snapshot(): AppLockSnapshot {
        updateLockState()
        return AppLockSnapshot(
            policy = stateStore.readPolicy(),
            locked = locked,
            lastUnlockTimestampMillis = stateStore.readLastUnlockTimestampMillis(),
        )
    }

    public fun isLocked(): Boolean {
        updateLockState()
        return locked
    }

    public fun lock() {
        locked = true
        stateStore.writeLastUnlockTimestampMillis(0L)
    }

    public fun unlock() {
        locked = false
        stateStore.writeLastUnlockTimestampMillis(clock())
    }

    public fun verifyCredential(rawCredential: String, algorithm: CredentialHashAlgorithm = CredentialHashAlgorithm.SHA_256): Boolean {
        val policy = stateStore.readPolicy()
        val actualHash = when (algorithm) {
            CredentialHashAlgorithm.SHA_256 -> AppLockHashing.sha256(rawCredential)
            CredentialHashAlgorithm.LEGACY_SHA_1 -> AppLockHashing.legacySha1(rawCredential)
        }
        val success = policy.credentialHash == actualHash
        if (success) unlock()
        return success
    }

    override fun onResume(owner: LifecycleOwner) {
        updateLockState()
    }

    override fun onStop(owner: LifecycleOwner) {
        shouldEvaluateLockOnResume = true
        if (!locked) stateStore.writeLastUnlockTimestampMillis(clock())
    }

    private fun updateLockState() {
        val policy = stateStore.readPolicy()
        if (!policy.enabled) {
            locked = false
            return
        }

        val elapsed = clock() - stateStore.readLastUnlockTimestampMillis()
        if (elapsed > policy.unlockTimeoutMillis && shouldEvaluateLockOnResume) {
            locked = true
            shouldEvaluateLockOnResume = false
        } else if (!locked) {
            stateStore.writeLastUnlockTimestampMillis(clock())
        }
    }
}

public enum class CredentialHashAlgorithm {
    SHA_256,
    LEGACY_SHA_1,
}
