package org.connecttag.lib.features.applock

/**
 * High-priority security events emitted by [AppLockManager] to allow consuming apps
 * (e.g. `Hazm`, `SoorNet`, `Tayf`) to trigger quarantine, wipe sensitive caches, or log forensic alerts.
 */
public sealed interface AppLockSecurityEvent {
    /**
     * Emitted when a user unlocks the lock screen using the configured Duress/Decoy credential.
     */
    public data class DuressTriggered(
        public val timestampMillis: Long,
        public val snapshot: AppLockSnapshot,
    ) : AppLockSecurityEvent

    /**
     * Emitted when consecutive failed authentication attempts reach or exceed
     * [AppLockAttemptPolicy.criticalFailureThreshold].
     */
    public data class CriticalFailureThresholdReached(
        public val failedAttempts: Int,
        public val threshold: Int,
        public val timestampMillis: Long,
        public val snapshot: AppLockSnapshot,
    ) : AppLockSecurityEvent

    /**
     * Emitted when [AppLockStateStore] detects offline tampering of persisted policy or lockout state.
     */
    public data class PolicyTamperDetected(
        public val timestampMillis: Long,
        public val snapshot: AppLockSnapshot,
    ) : AppLockSecurityEvent

    /**
     * Emitted when the user triggers an immediate panic lock via hardware key or rapid tap gesture.
     */
    public data class PanicLockTriggered(
        public val timestampMillis: Long,
        public val snapshot: AppLockSnapshot,
    ) : AppLockSecurityEvent
}

/**
 * Listener hook for reacting to [AppLockSecurityEvent] notifications.
 */
public fun interface AppLockSecurityHook {
    public fun onSecurityEvent(event: AppLockSecurityEvent)
}
