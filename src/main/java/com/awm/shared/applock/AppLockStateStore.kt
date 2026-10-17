package org.connecttag.features.applock

public interface AppLockStateStore {
    public fun readPolicy(): AppLockPolicy
    public fun writePolicy(policy: AppLockPolicy)
    public fun readLastUnlockTimestampMillis(): Long
    public fun writeLastUnlockTimestampMillis(timestampMillis: Long)
}
