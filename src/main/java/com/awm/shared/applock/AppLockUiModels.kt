package org.connecttag.features.applock

public data class AppLockScreenState(
    public val title: String = "Unlock",
    public val protectionType: AppLockProtectionType = AppLockProtectionType.PIN,
    public val enteredCredential: String = "",
    public val errorMessage: String? = null,
    public val lockedOutUntilMillis: Long? = null,
    public val canUseBiometric: Boolean = false,
    public val isVerifying: Boolean = false,
)

public data class AppLockSetupState(
    public val title: String = "Set app lock",
    public val selectedProtectionType: AppLockProtectionType = AppLockProtectionType.PIN,
    public val firstCredential: String = "",
    public val repeatedCredential: String = "",
    public val errorMessage: String? = null,
    public val canUseBiometric: Boolean = false,
)

public sealed interface AppLockEvent {
    public data object BackClicked : AppLockEvent
    public data object BiometricClicked : AppLockEvent
    public data object ClearClicked : AppLockEvent
    public data object SubmitClicked : AppLockEvent
    public data class DigitClicked(public val digit: Int) : AppLockEvent
    public data class CredentialChanged(public val value: String) : AppLockEvent
    public data class ProtectionTypeSelected(public val type: AppLockProtectionType) : AppLockEvent
}

public data class AppLockUiConfig(
    public val minPinLength: Int = 4,
    public val maxPinLength: Int = 10,
    public val wrongCredentialMessage: String = "Wrong credential",
    public val lockedOutMessage: String = "Try again later",
)
