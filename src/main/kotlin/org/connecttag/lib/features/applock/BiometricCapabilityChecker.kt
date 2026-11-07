package org.connecttag.lib.features.applock

import android.content.Context
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity

/**
 * Checks device biometric and device credential authentication capabilities.
 */
public class BiometricCapabilityChecker(
    private val context: Context,
) {
    public fun canAuthenticate(strongOnly: Boolean = false): Boolean {
        val authenticators = if (strongOnly) {
            BiometricManager.Authenticators.BIOMETRIC_STRONG
        } else {
            BiometricManager.Authenticators.BIOMETRIC_WEAK or BiometricManager.Authenticators.DEVICE_CREDENTIAL
        }
        return BiometricManager.from(context).canAuthenticate(authenticators) == BiometricManager.BIOMETRIC_SUCCESS
    }

    public fun canAuthenticateBiometricOnly(strongOnly: Boolean = false): Boolean {
        val authenticators = if (strongOnly) {
            BiometricManager.Authenticators.BIOMETRIC_STRONG
        } else {
            BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.BIOMETRIC_WEAK
        }
        return BiometricManager.from(context).canAuthenticate(authenticators) == BiometricManager.BIOMETRIC_SUCCESS
    }
}

/**
 * Configuration for presenting the system [BiometricPrompt] dialog.
 */
public data class AppLockBiometricPromptConfig(
    public val title: String = DEFAULT_TITLE,
    public val subtitle: String? = null,
    public val description: String? = null,
    public val negativeButtonText: String = DEFAULT_NEGATIVE_BUTTON_TEXT,
    public val strongAuthenticatorsOnly: Boolean = false,
    public val confirmationRequired: Boolean = false,
) {
    public companion object {
        public const val DEFAULT_TITLE: String = "المصادقة البيومترية"
        public const val DEFAULT_NEGATIVE_BUTTON_TEXT: String = "استخدام رمز PIN"
    }
}

/**
 * Outcome of a system biometric authentication prompt.
 */
public sealed interface AppLockBiometricResult {
    public data object Success : AppLockBiometricResult
    public data object Failed : AppLockBiometricResult
    public data object Cancelled : AppLockBiometricResult
    public data object LockedOut : AppLockBiometricResult
    public data object Unavailable : AppLockBiometricResult
    public data class Error(
        public val errorCode: Int,
        public val message: String,
    ) : AppLockBiometricResult
}

/**
 * Ready-to-use executor for AndroidX [BiometricPrompt] integrated with [AppLockManager].
 *
 * Ensures that an active PIN attempt cooldown lockout cannot be bypassed via biometrics,
 * and automatically unlocks [AppLockManager] upon successful biometric verification.
 */
public object AppLockBiometricAuthenticator {
    /**
     * Launches the system [BiometricPrompt] on [activity] and unlocks [manager] if authentication succeeds.
     */
    public fun authenticate(
        activity: FragmentActivity,
        config: AppLockBiometricPromptConfig = AppLockBiometricPromptConfig(),
        manager: AppLockManager? = null,
        onResult: (AppLockBiometricResult) -> Unit = {},
    ) {
        if (manager != null && manager.snapshot().attemptState.isLockedOut()) {
            onResult(AppLockBiometricResult.LockedOut)
            return
        }

        val capabilityChecker = BiometricCapabilityChecker(activity)
        if (!capabilityChecker.canAuthenticateBiometricOnly(config.strongAuthenticatorsOnly)) {
            onResult(AppLockBiometricResult.Unavailable)
            return
        }

        val executor = ContextCompat.getMainExecutor(activity)
        val prompt = BiometricPrompt(
            activity,
            executor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    manager?.unlock()
                    onResult(AppLockBiometricResult.Success)
                }

                override fun onAuthenticationFailed() {
                    onResult(AppLockBiometricResult.Failed)
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    val outcome = when (errorCode) {
                        BiometricPrompt.ERROR_USER_CANCELED,
                        BiometricPrompt.ERROR_NEGATIVE_BUTTON,
                        BiometricPrompt.ERROR_CANCELED,
                        -> AppLockBiometricResult.Cancelled

                        BiometricPrompt.ERROR_LOCKOUT,
                        BiometricPrompt.ERROR_LOCKOUT_PERMANENT,
                        -> AppLockBiometricResult.LockedOut

                        else -> AppLockBiometricResult.Error(errorCode, errString.toString())
                    }
                    onResult(outcome)
                }
            },
        )

        val authenticators = if (config.strongAuthenticatorsOnly) {
            BiometricManager.Authenticators.BIOMETRIC_STRONG
        } else {
            BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.BIOMETRIC_WEAK
        }

        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle(config.title)
            .apply {
                if (!config.subtitle.isNullOrBlank()) {
                    setSubtitle(config.subtitle)
                }
                if (!config.description.isNullOrBlank()) {
                    setDescription(config.description)
                }
            }
            .setNegativeButtonText(config.negativeButtonText)
            .setConfirmationRequired(config.confirmationRequired)
            .setAllowedAuthenticators(authenticators)
            .build()

        prompt.authenticate(promptInfo)
    }
}
