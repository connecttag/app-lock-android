package org.connecttag.features.applock

import android.content.Context
import androidx.biometric.BiometricManager

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
}
