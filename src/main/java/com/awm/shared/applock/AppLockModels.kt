package org.connecttag.features.applock

public enum class AppLockProtectionType {
    NONE,
    PIN,
    PATTERN,
    BIOMETRIC,
}

public data class AppLockPolicy(
    public val enabled: Boolean = false,
    public val protectionType: AppLockProtectionType = AppLockProtectionType.NONE,
    public val credentialHash: String = "",
    public val unlockTimeoutMillis: Long = DEFAULT_UNLOCK_TIMEOUT_MILLIS,
) {
    public companion object {
        public const val DEFAULT_UNLOCK_TIMEOUT_MILLIS: Long = 30_000L
    }
}

public data class AppLockSnapshot(
    public val policy: AppLockPolicy,
    public val locked: Boolean,
    public val lastUnlockTimestampMillis: Long,
)
