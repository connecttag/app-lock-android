package org.connecttag.lib.features.applock

import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner
import java.util.concurrent.CopyOnWriteArrayList
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Lifecycle-aware application lock coordinator managing session authentication,
 * Master & Duress PIN verification, cooldown attempt tracking, integrity tamper checks,
 * security hooks, and panic lock gestures.
 */
public class AppLockManager(
    private val stateStore: AppLockStateStore,
    private val clock: () -> Long = System::currentTimeMillis,
    private val attemptTracker: AppLockAttemptTracker = AppLockAttemptTracker(
        clock = clock,
        initialState = stateStore.readAttemptState(),
    ),
    public val pinValidator: PinValidator = PinValidator(),
    private val pinHasher: PinHasher = Pbkdf2PinHasher(pinValidator),
    private val autoUpgradeLegacyHashes: Boolean = true,
    initialSecurityHooks: List<AppLockSecurityHook> = emptyList(),
) : DefaultLifecycleObserver {

    private val securityHooks: CopyOnWriteArrayList<AppLockSecurityHook> =
        CopyOnWriteArrayList(initialSecurityHooks)

    @Volatile
    private var locked: Boolean = stateStore.readPolicy().enabled || !stateStore.isIntegrityValid()

    @Volatile
    private var forceLocked: Boolean = !stateStore.isIntegrityValid()

    @Volatile
    private var shouldEvaluateLockOnResume: Boolean = true

    @Volatile
    private var lastTapTimestampMillis: Long = 0L

    @Volatile
    private var consecutiveTapCount: Int = 0

    @Volatile
    private var activeTapTargetKey: String = ""

    private val mutableSnapshotFlow: MutableStateFlow<AppLockSnapshot> = MutableStateFlow(buildSnapshot())

    /**
     * Reactive stream of [AppLockSnapshot] for Compose UI and ViewModel consumers.
     */
    public val snapshotFlow: StateFlow<AppLockSnapshot> = mutableSnapshotFlow.asStateFlow()

    /**
     * Registers a listener hook to receive [AppLockSecurityEvent] callbacks.
     */
    public fun registerSecurityHook(hook: AppLockSecurityHook) {
        if (hook !in securityHooks) {
            securityHooks.add(hook)
        }
    }

    /**
     * Unregisters a previously registered [AppLockSecurityHook].
     */
    public fun unregisterSecurityHook(hook: AppLockSecurityHook) {
        securityHooks.remove(hook)
    }

    public fun snapshot(): AppLockSnapshot {
        updateLockState()
        return publishSnapshot()
    }

    public fun isLocked(): Boolean {
        updateLockState()
        publishSnapshot()
        return locked
    }

    /**
     * Resolves the current fail-closed [AppLockGateMode] taking into account whether persistent
     * security state has finished loading (`isStateLoaded`), encountered a read failure (`loadFailed`),
     * or failed integrity verification (`tamperDetected`).
     */
    public fun resolveGateMode(
        isStateLoaded: Boolean = true,
        loadFailed: Boolean = false,
    ): AppLockGateMode {
        if (!isStateLoaded || loadFailed) {
            return AppLockGateMode.LOADING
        }
        val currentSnapshot = snapshot()
        return AppLockGateResolver.resolve(
            policy = currentSnapshot.policy,
            isAuthenticated = !currentSnapshot.locked,
            forceLocked = forceLocked,
            loadFailed = false,
            tamperDetected = currentSnapshot.tamperDetected,
        )
    }

    public fun lock() {
        locked = true
        forceLocked = true
        stateStore.writeLastUnlockTimestampMillis(0L)
        publishSnapshot()
    }

    public fun unlock() {
        locked = false
        forceLocked = false
        val currentPolicy = stateStore.readPolicy()
        if (currentPolicy.decoyActive) {
            stateStore.writePolicy(currentPolicy.copy(decoyActive = false))
        }
        val clearedAttempts = attemptTracker.recordSuccess()
        stateStore.writeAttemptState(clearedAttempts)
        stateStore.writeLastUnlockTimestampMillis(clock())
        publishSnapshot()
    }

    /**
     * Updates non-credential behavioral flags on [AppLockPolicy] (such as [allowBiometricUnlock],
     * [scrambleKeypad], [secureRecentsEnabled], [panicLockGestureEnabled], and [unlockTimeoutMillis]).
     */
    public fun updatePolicySettings(
        allowBiometricUnlock: Boolean? = null,
        scrambleKeypad: Boolean? = null,
        secureRecentsEnabled: Boolean? = null,
        panicLockGestureEnabled: Boolean? = null,
        unlockTimeoutMillis: Long? = null,
    ): AppLockPolicy {
        val current = stateStore.readPolicy()
        val updated = current.copy(
            allowBiometricUnlock = allowBiometricUnlock ?: current.allowBiometricUnlock,
            scrambleKeypad = scrambleKeypad ?: current.scrambleKeypad,
            secureRecentsEnabled = secureRecentsEnabled ?: current.secureRecentsEnabled,
            panicLockGestureEnabled = panicLockGestureEnabled ?: current.panicLockGestureEnabled,
            unlockTimeoutMillis = unlockTimeoutMillis ?: current.unlockTimeoutMillis,
        )
        stateStore.writePolicy(updated)
        publishSnapshot()
        return updated
    }

    /**
     * Verifies [rawCredential] against the primary Master credential hash.
     * Preserved for backward compatibility; for Master + Duress and lockout evaluation, prefer [evaluateCredential].
     */
    public fun verifyCredential(
        rawCredential: String,
        algorithm: CredentialHashAlgorithm = stateStore.readPolicy().hashAlgorithm,
    ): Boolean {
        val outcome = evaluateCredential(rawCredential, algorithm)
        return outcome.result == AppLockUnlockResult.MASTER
    }

    /**
     * Evaluates a single [rawCredential] against lockout state, Master credential, and optional Duress credential.
     */
    public fun evaluateCredential(
        rawCredential: String,
        algorithm: CredentialHashAlgorithm = stateStore.readPolicy().hashAlgorithm,
    ): AppLockVerificationOutcome = evaluateCandidateCredentials(
        candidates = listOf(rawCredential),
        algorithm = algorithm,
    )

    /**
     * Evaluates multiple candidate inputs in order (useful for disguise tools where user may type code in title or body).
     */
    public fun evaluateCandidateCredentials(
        candidates: List<String>,
        algorithm: CredentialHashAlgorithm = stateStore.readPolicy().hashAlgorithm,
    ): AppLockVerificationOutcome {
        val now = clock()
        if (attemptTracker.snapshot().isLockedOut(now)) {
            return AppLockVerificationOutcome(
                result = AppLockUnlockResult.LOCKED_OUT,
                snapshot = publishSnapshot(),
            )
        }

        val policy = stateStore.readPolicy()
        if (!stateStore.isIntegrityValid()) {
            val tamperSnapshot = publishSnapshot()
            dispatchSecurityEvent(
                AppLockSecurityEvent.PolicyTamperDetected(
                    timestampMillis = now,
                    snapshot = tamperSnapshot,
                ),
            )
        }

        val distinctCandidates = candidates
            .map { raw -> PinNormalizer.normalize(raw) }
            .filter { normalized -> normalized.isNotEmpty() }
            .distinct()

        for (candidate in distinctCandidates) {
            if (policy.isMasterCredentialConfigured &&
                matchesSecret(candidate, policy.credentialHash, algorithm)
            ) {
                maybeUpgradeMasterHash(policy, candidate)
                unlock()
                return AppLockVerificationOutcome(
                    result = AppLockUnlockResult.MASTER,
                    snapshot = publishSnapshot(),
                )
            }

            if (policy.isDuressCredentialConfigured &&
                matchesSecret(candidate, policy.duressCredentialHash, algorithm)
            ) {
                val upgradedPolicy = maybeUpgradeDuressHash(policy, candidate)
                activateDecoyMode(upgradedPolicy)
                val decoySnapshot = publishSnapshot()
                dispatchSecurityEvent(
                    AppLockSecurityEvent.DuressTriggered(
                        timestampMillis = now,
                        snapshot = decoySnapshot,
                    ),
                )
                return AppLockVerificationOutcome(
                    result = AppLockUnlockResult.DURESS,
                    snapshot = decoySnapshot,
                )
            }
        }

        val updatedAttempts = attemptTracker.recordFailure()
        stateStore.writeAttemptState(updatedAttempts)
        val failureSnapshot = publishSnapshot()

        val criticalThreshold = attemptTracker.policy.criticalFailureThreshold
        if (criticalThreshold != null && updatedAttempts.failedAttempts >= criticalThreshold) {
            dispatchSecurityEvent(
                AppLockSecurityEvent.CriticalFailureThresholdReached(
                    failedAttempts = updatedAttempts.failedAttempts,
                    threshold = criticalThreshold,
                    timestampMillis = now,
                    snapshot = failureSnapshot,
                ),
            )
        }

        return AppLockVerificationOutcome(
            result = if (updatedAttempts.isLockedOut(clock())) {
                AppLockUnlockResult.LOCKED_OUT
            } else {
                AppLockUnlockResult.INVALID
            },
            snapshot = failureSnapshot,
        )
    }

    /**
     * Configures or updates the Master PIN and optional Duress PIN after validating policy rules.
     */
    public fun configurePinCredentials(
        masterPin: String,
        duressPin: String? = null,
        currentPin: String? = null,
        enableImmediately: Boolean = true,
    ): PinConfigurationResult {
        val currentPolicy = stateStore.readPolicy()
        if (currentPolicy.isMasterCredentialConfigured && currentPolicy.enabled) {
            val verifiedCurrent = currentPin != null &&
                matchesSecret(currentPin, currentPolicy.credentialHash, currentPolicy.hashAlgorithm)
            if (!verifiedCurrent) {
                return PinConfigurationResult.CurrentPinInvalid
            }
        }

        val masterValidation = pinValidator.validate(masterPin)
        if (!masterValidation.isValid) {
            return PinConfigurationResult.MasterPinInvalid(masterValidation)
        }

        val normalizedDuress = duressPin?.let { PinNormalizer.normalize(it) }.orEmpty()
        if (normalizedDuress.isNotEmpty()) {
            val duressValidation = pinValidator.validate(
                rawPin = normalizedDuress,
                primaryPinForComparison = masterValidation.normalizedPin,
            )
            if (!duressValidation.isDistinctFromPrimary) {
                return PinConfigurationResult.DuplicateMasterAndDuressPin
            }
            if (!duressValidation.isValid) {
                return PinConfigurationResult.DuressPinInvalid(duressValidation)
            }
        }

        val encodedMaster = pinHasher.encode(masterValidation.normalizedPin)
        val encodedDuress = if (normalizedDuress.isNotEmpty()) {
            pinHasher.encode(normalizedDuress)
        } else {
            ""
        }

        val updatedPolicy = currentPolicy.copy(
            enabled = enableImmediately,
            protectionType = AppLockProtectionType.PIN,
            credentialHash = encodedMaster,
            duressCredentialHash = encodedDuress,
            hashAlgorithm = CredentialHashAlgorithm.PBKDF2_HMAC_SHA256,
            decoyActive = false,
        )
        stateStore.writePolicy(updatedPolicy)
        unlock()
        return PinConfigurationResult.Success(updatedPolicy)
    }

    /**
     * Disables app lock and optionally clears stored credentials if [clearStoredCredentials] is `true`.
     */
    public fun disableAppLock(
        currentPin: String? = null,
        requireCurrentPinIfEnabled: Boolean = false,
        clearStoredCredentials: Boolean = true,
    ): Boolean {
        val policy = stateStore.readPolicy()
        if (requireCurrentPinIfEnabled && policy.enabled && policy.isMasterCredentialConfigured) {
            val valid = currentPin != null &&
                matchesSecret(currentPin, policy.credentialHash, policy.hashAlgorithm)
            if (!valid) return false
        }

        val nextPolicy = if (clearStoredCredentials) {
            policy.copy(
                enabled = false,
                protectionType = AppLockProtectionType.NONE,
                credentialHash = "",
                duressCredentialHash = "",
                decoyActive = false,
            )
        } else {
            policy.copy(enabled = false, decoyActive = false)
        }
        stateStore.writePolicy(nextPolicy)
        locked = false
        forceLocked = false
        val clearedAttempts = attemptTracker.recordSuccess()
        stateStore.writeAttemptState(clearedAttempts)
        publishSnapshot()
        return true
    }

    /**
     * Registers a tap or hardware key press (e.g. triple Volume-Down panic lock or multi-tap hidden unlock).
     * Returns `true` when [requiredTaps] occurs within [windowMillis] for the same [targetKey].
     */
    public fun registerTapSequence(
        targetKey: String,
        requiredTaps: Int = DEFAULT_PANIC_TAP_COUNT,
        windowMillis: Long = DEFAULT_PANIC_WINDOW_MILLIS,
    ): Boolean {
        require(requiredTaps >= 1) { "requiredTaps must be at least 1" }
        val now = clock()
        consecutiveTapCount = if (
            activeTapTargetKey == targetKey &&
            now - lastTapTimestampMillis <= windowMillis
        ) {
            consecutiveTapCount + 1
        } else {
            1
        }
        activeTapTargetKey = targetKey
        lastTapTimestampMillis = now

        if (consecutiveTapCount < requiredTaps) return false
        consecutiveTapCount = 0
        return true
    }

    /**
     * Convenience handler for hardware Volume-Down key presses to trigger panic lock when enabled.
     */
    public fun onPanicTriggerKeyPressed(): Boolean {
        val policy = stateStore.readPolicy()
        if (!policy.enabled || !policy.panicLockGestureEnabled || locked) return false
        if (registerTapSequence(PANIC_GESTURE_TARGET_KEY, DEFAULT_PANIC_TAP_COUNT, DEFAULT_PANIC_WINDOW_MILLIS)) {
            lock()
            dispatchSecurityEvent(
                AppLockSecurityEvent.PanicLockTriggered(
                    timestampMillis = clock(),
                    snapshot = snapshotFlow.value,
                ),
            )
            return true
        }
        return false
    }

    override fun onResume(owner: LifecycleOwner) {
        updateLockState()
        publishSnapshot()
    }

    override fun onStop(owner: LifecycleOwner) {
        shouldEvaluateLockOnResume = true
        val policy = stateStore.readPolicy()
        if (policy.enabled && policy.unlockTimeoutMillis <= 0L) {
            lock()
        } else if (!locked) {
            stateStore.writeLastUnlockTimestampMillis(clock())
            publishSnapshot()
        }
    }

    private fun activateDecoyMode(policy: AppLockPolicy) {
        val updatedPolicy = policy.copy(decoyActive = true)
        stateStore.writePolicy(updatedPolicy)
        locked = true
        forceLocked = false
        val clearedAttempts = attemptTracker.recordSuccess()
        stateStore.writeAttemptState(clearedAttempts)
    }

    private fun maybeUpgradeMasterHash(
        policy: AppLockPolicy,
        normalizedCandidate: String,
    ) {
        if (!autoUpgradeLegacyHashes || !pinValidator.isValidPin(normalizedCandidate)) return
        val needsUpgrade = policy.hashAlgorithm != CredentialHashAlgorithm.PBKDF2_HMAC_SHA256 ||
            pinHasher.needsRehash(policy.credentialHash)
        if (!needsUpgrade) return

        val upgradedMaster = runCatching { pinHasher.encode(normalizedCandidate) }.getOrNull() ?: return
        val canPromoteAlgorithm = !policy.isDuressCredentialConfigured ||
            !pinHasher.needsRehash(policy.duressCredentialHash)
        stateStore.writePolicy(
            policy.copy(
                credentialHash = upgradedMaster,
                hashAlgorithm = if (canPromoteAlgorithm) {
                    CredentialHashAlgorithm.PBKDF2_HMAC_SHA256
                } else {
                    policy.hashAlgorithm
                },
            ),
        )
    }

    private fun maybeUpgradeDuressHash(
        policy: AppLockPolicy,
        normalizedCandidate: String,
    ): AppLockPolicy {
        if (!autoUpgradeLegacyHashes || !pinValidator.isValidPin(normalizedCandidate)) return policy
        val needsUpgrade = policy.hashAlgorithm != CredentialHashAlgorithm.PBKDF2_HMAC_SHA256 ||
            pinHasher.needsRehash(policy.duressCredentialHash)
        if (!needsUpgrade) return policy

        val upgradedDuress = runCatching { pinHasher.encode(normalizedCandidate) }.getOrNull() ?: return policy
        val canPromoteAlgorithm = !policy.isMasterCredentialConfigured ||
            !pinHasher.needsRehash(policy.credentialHash)
        val updated = policy.copy(
            duressCredentialHash = upgradedDuress,
            hashAlgorithm = if (canPromoteAlgorithm) {
                CredentialHashAlgorithm.PBKDF2_HMAC_SHA256
            } else {
                policy.hashAlgorithm
            },
        )
        stateStore.writePolicy(updated)
        return updated
    }

    private fun matchesSecret(
        rawCredential: String,
        storedHash: String,
        algorithm: CredentialHashAlgorithm,
    ): Boolean {
        if (storedHash.isBlank()) return false
        return if (algorithm == CredentialHashAlgorithm.PBKDF2_HMAC_SHA256 &&
            (':' in storedHash || storedHash.startsWith("pbkdf2_sha256$"))
        ) {
            pinHasher.matches(rawCredential, storedHash) ||
                AppLockHashing.verify(rawCredential, storedHash, algorithm)
        } else {
            AppLockHashing.verify(rawCredential, storedHash, algorithm)
        }
    }

    private fun updateLockState() {
        val policy = stateStore.readPolicy()
        val integrityValid = stateStore.isIntegrityValid()
        if (!integrityValid) {
            locked = true
            forceLocked = true
            return
        }

        if (!policy.enabled) {
            locked = false
            forceLocked = false
            return
        }

        if (forceLocked || policy.decoyActive) {
            locked = true
            return
        }

        val elapsed = clock() - stateStore.readLastUnlockTimestampMillis()
        if (elapsed > policy.unlockTimeoutMillis && shouldEvaluateLockOnResume) {
            locked = true
            shouldEvaluateLockOnResume = false
        } else if (!locked) {
            stateStore.writeLastUnlockTimestampMillis(clock())
        }
    }

    private fun buildSnapshot(): AppLockSnapshot {
        val policy = stateStore.readPolicy()
        val integrityValid = stateStore.isIntegrityValid()
        val currentAttempts = attemptTracker.snapshot()
        return AppLockSnapshot(
            policy = policy,
            locked = locked || !integrityValid,
            lastUnlockTimestampMillis = stateStore.readLastUnlockTimestampMillis(),
            gateMode = AppLockGateResolver.resolve(
                policy = policy,
                isAuthenticated = !locked && integrityValid,
                forceLocked = forceLocked,
                tamperDetected = !integrityValid,
            ),
            attemptState = currentAttempts,
            tamperDetected = !integrityValid,
        )
    }

    private fun publishSnapshot(): AppLockSnapshot {
        val next = buildSnapshot()
        mutableSnapshotFlow.value = next
        return next
    }

    private fun dispatchSecurityEvent(event: AppLockSecurityEvent) {
        securityHooks.forEach { hook ->
            runCatching { hook.onSecurityEvent(event) }
        }
    }

    public companion object {
        public const val PANIC_GESTURE_TARGET_KEY: String = "panicLockKey"
        public const val DEFAULT_PANIC_TAP_COUNT: Int = 3
        public const val DEFAULT_PANIC_WINDOW_MILLIS: Long = 800L
    }
}
