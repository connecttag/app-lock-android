package org.connecttag.features.applock

public data class AppLockAttemptPolicy(
    public val maxAttempts: Int = 3,
    public val lockoutMillis: Long = 5_000L,
)

public data class AppLockAttemptState(
    public val failedAttempts: Int = 0,
    public val lockedOutUntilMillis: Long? = null,
) {
    public fun isLockedOut(nowMillis: Long = System.currentTimeMillis()): Boolean =
        lockedOutUntilMillis?.let { it > nowMillis } ?: false
}

public class AppLockAttemptTracker(
    private val policy: AppLockAttemptPolicy = AppLockAttemptPolicy(),
    private val clock: () -> Long = System::currentTimeMillis,
) {
    private var state: AppLockAttemptState = AppLockAttemptState()

    public fun snapshot(): AppLockAttemptState = state

    public fun recordSuccess(): AppLockAttemptState {
        state = AppLockAttemptState()
        return state
    }

    public fun recordFailure(): AppLockAttemptState {
        val failedAttempts = state.failedAttempts + 1
        state = if (failedAttempts >= policy.maxAttempts) {
            AppLockAttemptState(
                failedAttempts = failedAttempts,
                lockedOutUntilMillis = clock() + policy.lockoutMillis,
            )
        } else {
            state.copy(failedAttempts = failedAttempts)
        }
        return state
    }
}
