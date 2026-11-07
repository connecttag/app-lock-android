# App Lock Android (`:features:app-lock-android`)

Core Android & PIN lock security engine providing lifecycle-aware session locking, salted `PBKDF2WithHmacSHA256` PIN hashing, hardware-backed `HmacSHA256` policy tamper detection, Master + Duress (decoy/camouflage) PIN evaluation, Unicode/Arabic-Indic digit normalization, progressive attempt lockout tracking, fail-closed gate resolution, integrated `BiometricPrompt` execution, launcher `<activity-alias>` camouflage switching, and `FLAG_SECURE` window privacy management.

## Key Capabilities

- **`Pbkdf2PinHasher` & `AppLockHashing`:** Salted `PBKDF2WithHmacSHA256` (`120,000` iterations, `16-byte` cryptographic salt, constant-time `MessageDigest.isEqual`) with transparent automatic upgrade from legacy `SHA-256` and `SHA-1` hashes upon unlock.
- **`AppLockIntegritySigner` (`AndroidKeystoreHmacSigner` & `JvmHmacIntegritySigner`):** Signs persisted `AppLockPolicy` and `AppLockAttemptState` records using an Android Keystore `HmacSHA256` key to detect and fail-close against offline `SharedPreferences` XML tampering.
- **`PinNormalizer` & `PinValidator`:** Canonicalizes Arabic-Indic (`٠-٩`) and Eastern Arabic (`۰-۹`) digits into ASCII `0-9`, and validates configurable length, format, repetition, sequential rules, Master/Duress distinctness, and custom `PinRuleEvaluator` plugins.
- **`AppLockManager` & `AppLockGateResolver`:** Lifecycle-aware coordinator (`DefaultLifecycleObserver`) with reactive `StateFlow<AppLockSnapshot>`, Master (`MASTER`) vs Duress (`DURESS`) credential evaluation, fail-closed `AppLockGateMode` (`LOADING`, `UNLOCKED`, `LOCKED`, `DECOY`), and multi-tap panic lock gesture detection.
- **`AppLockSecurityHook`:** Dispatches `AppLockSecurityEvent` callbacks (`DuressTriggered`, `CriticalFailureThresholdReached`, `PolicyTamperDetected`, `PanicLockTriggered`) for emergency cache wiping or security quarantine.
- **`AppLockBiometricAuthenticator` & `BiometricCapabilityChecker`:** Ready-to-use `BiometricPrompt` executor integrated with `AppLockManager` and lockout enforcement.
- **`AppLauncherAliasController`:** Fail-safe `<activity-alias>` switcher for disguising the application icon and label in the launcher while guaranteeing at least one launcher component remains active.
- **`AppLockWindowPrivacyController`:** Reference-counted `FLAG_SECURE` and Android Recents task description masking.
