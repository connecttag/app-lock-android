package org.connecttag.features.applock

import android.content.Context
import android.content.SharedPreferences

public class SharedPreferencesAppLockStateStore(
    context: Context,
    preferencesName: String = DEFAULT_PREFERENCES_NAME,
) : AppLockStateStore {
    private val preferences: SharedPreferences = context.applicationContext.getSharedPreferences(
        preferencesName,
        Context.MODE_PRIVATE,
    )

    override fun readPolicy(): AppLockPolicy = AppLockPolicy(
        enabled = preferences.getBoolean(KEY_ENABLED, false),
        protectionType = runCatching {
            AppLockProtectionType.valueOf(preferences.getString(KEY_PROTECTION_TYPE, AppLockProtectionType.NONE.name).orEmpty())
        }.getOrDefault(AppLockProtectionType.NONE),
        credentialHash = preferences.getString(KEY_CREDENTIAL_HASH, "").orEmpty(),
        unlockTimeoutMillis = preferences.getLong(KEY_UNLOCK_TIMEOUT, AppLockPolicy.DEFAULT_UNLOCK_TIMEOUT_MILLIS),
    )

    override fun writePolicy(policy: AppLockPolicy) {
        preferences.edit()
            .putBoolean(KEY_ENABLED, policy.enabled)
            .putString(KEY_PROTECTION_TYPE, policy.protectionType.name)
            .putString(KEY_CREDENTIAL_HASH, policy.credentialHash)
            .putLong(KEY_UNLOCK_TIMEOUT, policy.unlockTimeoutMillis)
            .apply()
    }

    override fun readLastUnlockTimestampMillis(): Long = preferences.getLong(KEY_LAST_UNLOCK, 0L)

    override fun writeLastUnlockTimestampMillis(timestampMillis: Long) {
        preferences.edit().putLong(KEY_LAST_UNLOCK, timestampMillis).apply()
    }

    public companion object {
        public const val DEFAULT_PREFERENCES_NAME: String = "app_lock"
        private const val KEY_ENABLED = "enabled"
        private const val KEY_PROTECTION_TYPE = "protection_type"
        private const val KEY_CREDENTIAL_HASH = "credential_hash"
        private const val KEY_UNLOCK_TIMEOUT = "unlock_timeout"
        private const val KEY_LAST_UNLOCK = "last_unlock"
    }
}
