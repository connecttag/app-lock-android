package org.connecttag.lib.features.applock

/**
 * Operational mode for a PIN lock screen.
 */
public enum class PinScreenMode {
    /** Prompts the user to enter an existing PIN to unlock the application. */
    AUTHENTICATE,

    /** Guides the user through creating and confirming a new PIN. */
    CREATE,

    /** Verifies the current PIN before guiding the user through creating a new PIN. */
    CHANGE,
}

/**
 * Step within the multi-step PIN creation or change workflow.
 */
public enum class PinSetupStep {
    VERIFY_CURRENT,
    ENTER_NEW,
    CONFIRM_NEW,
}

/**
 * UI state representation for an active unlock screen.
 */
public data class AppLockScreenState(
    public val title: String = DEFAULT_UNLOCK_TITLE,
    public val subtitle: String? = null,
    public val protectionType: AppLockProtectionType = AppLockProtectionType.PIN,
    public val enteredCredential: String = "",
    public val errorMessage: String? = null,
    public val lockedOutUntilMillis: Long? = null,
    public val failedAttempts: Int = 0,
    public val canUseBiometric: Boolean = false,
    public val isVerifying: Boolean = false,
) {
    public companion object {
        public const val DEFAULT_UNLOCK_TITLE: String = "Unlock"
    }
}

/**
 * UI state representation for a PIN/credential setup or modification screen.
 */
public data class AppLockSetupState(
    public val title: String = DEFAULT_SETUP_TITLE,
    public val subtitle: String? = null,
    public val step: PinSetupStep = PinSetupStep.ENTER_NEW,
    public val selectedProtectionType: AppLockProtectionType = AppLockProtectionType.PIN,
    public val currentCredential: String = "",
    public val firstCredential: String = "",
    public val repeatedCredential: String = "",
    public val errorMessage: String? = null,
    public val canUseBiometric: Boolean = false,
) {
    public companion object {
        public const val DEFAULT_SETUP_TITLE: String = "Set app lock"
    }
}

/**
 * User interaction events emitted by App Lock and PIN pad UI surfaces.
 */
public sealed interface AppLockEvent {
    public data object BackClicked : AppLockEvent
    public data object BiometricClicked : AppLockEvent
    public data object ClearClicked : AppLockEvent
    public data object BackspaceClicked : AppLockEvent
    public data object SubmitClicked : AppLockEvent
    public data class DigitClicked(public val digit: Int) : AppLockEvent
    public data class CredentialChanged(public val value: String) : AppLockEvent
    public data class ProtectionTypeSelected(public val type: AppLockProtectionType) : AppLockEvent
}

/**
 * Configurable UI behavior and localized message defaults for PIN lock screens.
 */
public data class AppLockUiConfig(
    public val minPinLength: Int = DEFAULT_MIN_PIN_LENGTH,
    public val maxPinLength: Int = DEFAULT_MAX_PIN_LENGTH,
    public val autoSubmitPinLength: Int? = DEFAULT_AUTO_SUBMIT_PIN_LENGTH,
    public val maskEnteredDigits: Boolean = true,
    public val wrongCredentialMessage: String = DEFAULT_WRONG_CREDENTIAL_MESSAGE,
    public val mismatchCredentialMessage: String = DEFAULT_MISMATCH_CREDENTIAL_MESSAGE,
    public val lockedOutMessage: String = DEFAULT_LOCKED_OUT_MESSAGE,
) {
    public companion object {
        public const val DEFAULT_MIN_PIN_LENGTH: Int = 4
        public const val DEFAULT_MAX_PIN_LENGTH: Int = 10
        public const val DEFAULT_AUTO_SUBMIT_PIN_LENGTH: Int = 4
        public const val DEFAULT_WRONG_CREDENTIAL_MESSAGE: String = "Wrong credential"
        public const val DEFAULT_MISMATCH_CREDENTIAL_MESSAGE: String = "PINs do not match"
        public const val DEFAULT_LOCKED_OUT_MESSAGE: String = "Try again later"
    }
}
