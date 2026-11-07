package org.connecttag.lib.features.applock

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Policy governing failed credential attempts, temporary lockout cooldowns, and critical security alerts.
 */
public data class AppLockAttemptPolicy(
    public val maxAttempts: Int = DEFAULT_MAX_ATTEMPTS,
    public val lockoutMillis: Long = DEFAULT_LOCKOUT_MILLIS,
    public val progressiveMultiplier: Int = DEFAULT_PROGRESSIVE_MULTIPLIER,
    public val criticalFailureThreshold: Int? = null,
) {
    init {
        require(maxAttempts >= MIN_MAX_ATTEMPTS) {
            "maxAttempts ($maxAttempts) must be at least $MIN_MAX_ATTEMPTS"
        }
        require(lockoutMillis >= MIN_LOCKOUT_MILLIS) {
            "lockoutMillis ($lockoutMillis) must be non-negative"
        }
        require(progressiveMultiplier >= MIN_PROGRESSIVE_MULTIPLIER) {
            "progressiveMultiplier ($progressiveMultiplier) must be at least $MIN_PROGRESSIVE_MULTIPLIER"
        }
        require(criticalFailureThreshold == null || criticalFailureThreshold >= maxAttempts) {
            "criticalFailureThreshold ($criticalFailureThreshold) must be >= maxAttempts ($maxAttempts)"
        }
    }

    public companion object {
        public const val DEFAULT_MAX_ATTEMPTS: Int = 3
        public const val DEFAULT_LOCKOUT_MILLIS: Long = 5_000L
        public const val DEFAULT_PROGRESSIVE_MULTIPLIER: Int = 1
        public const val DEFAULT_CRITICAL_FAILURE_THRESHOLD: Int = 10
        private const val MIN_MAX_ATTEMPTS: Int = 1
        private const val MIN_LOCKOUT_MILLIS: Long = 0L
        private const val MIN_PROGRESSIVE_MULTIPLIER: Int = 1
    }
}

/**
 * Immutable snapshot of failed unlock attempts and active lockout deadline.
 */
public data class AppLockAttemptState(
    public val failedAttempts: Int = 0,
    public val lockedOutUntilMillis: Long? = null,
) {
    /**
     * Returns `true` if a lockout window is active at [nowMillis].
     */
    public fun isLockedOut(nowMillis: Long = System.currentTimeMillis()): Boolean =
        lockedOutUntilMillis?.let { deadline -> deadline > nowMillis } ?: false

    /**
     * Returns the remaining lockout duration in milliseconds at [nowMillis], or `0L` if not locked out.
     */
    public fun remainingLockoutMillis(nowMillis: Long = System.currentTimeMillis()): Long =
        lockedOutUntilMillis?.let { deadline -> (deadline - nowMillis).coerceAtLeast(0L) } ?: 0L
}

/**
 * Tracks consecutive failed authentication attempts and computes cooldown lockout deadlines.
 */
public class AppLockAttemptTracker(
    public val policy: AppLockAttemptPolicy = AppLockAttemptPolicy(),
    private val clock: () -> Long = System::currentTimeMillis,
    initialState: AppLockAttemptState = AppLockAttemptState(),
) {
    private val mutableState: MutableStateFlow<AppLockAttemptState> = MutableStateFlow(initialState)

    /**
     * Reactive stream of attempt and lockout state for UI observation.
     */
    public val stateFlow: StateFlow<AppLockAttemptState> = mutableState.asStateFlow()

    public fun snapshot(): AppLockAttemptState = mutableState.value

    public fun isLockedOut(): Boolean = mutableState.value.isLockedOut(clock())

    public fun restore(restoredState: AppLockAttemptState) {
        mutableState.value = restoredState
    }

    public fun recordSuccess(): AppLockAttemptState {
        val cleared = AppLockAttemptState()
        mutableState.value = cleared
        return cleared
    }

    public fun recordFailure(): AppLockAttemptState {
        val now = clock()
        val current = mutableState.value
        val failedAttempts = current.failedAttempts + 1
        val nextState = if (failedAttempts >= policy.maxAttempts &&
            failedAttempts % policy.maxAttempts == 0
        ) {
            val lockoutCycle = (failedAttempts / policy.maxAttempts).coerceAtLeast(1)
            val multiplier = calculateMultiplier(lockoutCycle)
            AppLockAttemptState(
                failedAttempts = failedAttempts,
                lockedOutUntilMillis = now + (policy.lockoutMillis * multiplier),
            )
        } else {
            AppLockAttemptState(
                failedAttempts = failedAttempts,
                lockedOutUntilMillis = current.lockedOutUntilMillis?.takeIf { deadline -> deadline > now },
            )
        }
        mutableState.value = nextState
        return nextState
    }

    private fun calculateMultiplier(cycle: Int): Long {
        if (policy.progressiveMultiplier <= 1 || cycle <= 1) return 1L
        var factor = 1L
        repeat((cycle - 1).coerceAtMost(MAX_EXPONENT_STEPS)) {
            factor *= policy.progressiveMultiplier.toLong()
        }
        return factor
    }

    public companion object {
        private const val MAX_EXPONENT_STEPS: Int = 6
    }
}
