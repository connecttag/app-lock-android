package org.connecttag.lib.features.applock

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

public class AppLockSuiteTest {

    @Test
    public fun unreadOrFailedSecurityPolicyNeverExposesTheApp() {
        assertEquals(
            AppLockGateMode.LOADING,
            AppLockGateResolver.resolve(policy = null, isAuthenticated = true),
        )
        assertEquals(
            AppLockGateMode.LOADING,
            AppLockGateResolver.resolve(
                policy = AppLockPolicy(enabled = true),
                isAuthenticated = true,
                loadFailed = true,
            ),
        )
        assertEquals(
            AppLockGateMode.LOCKED,
            AppLockGateResolver.resolve(
                policy = AppLockPolicy(enabled = false),
                isAuthenticated = true,
                tamperDetected = true,
            ),
        )
    }

    @Test
    public fun coldLaunchAndPanicLockRequireAuthentication() {
        val enabledPolicy = AppLockPolicy(enabled = true)
        assertEquals(
            AppLockGateMode.LOCKED,
            AppLockGateResolver.resolve(
                policy = enabledPolicy,
                isAuthenticated = false,
                forceLocked = false,
            ),
        )
        assertEquals(
            AppLockGateMode.UNLOCKED,
            AppLockGateResolver.resolve(
                policy = enabledPolicy,
                isAuthenticated = true,
                forceLocked = false,
            ),
        )
        assertEquals(
            AppLockGateMode.LOCKED,
            AppLockGateResolver.resolve(
                policy = enabledPolicy,
                isAuthenticated = true,
                forceLocked = true,
            ),
        )
    }

    @Test
    public fun persistentlyActiveDuressModeTakesPrecedenceOverAuthenticatedSession() {
        val decoyPolicy = AppLockPolicy(enabled = true, decoyActive = true)
        assertEquals(
            AppLockGateMode.DECOY,
            AppLockGateResolver.resolve(policy = decoyPolicy, isAuthenticated = true),
        )
        assertEquals(
            AppLockGateMode.DECOY,
            AppLockGateResolver.resolve(policy = decoyPolicy, isAuthenticated = false),
        )
    }

    @Test
    public fun pbkdf2CodesAreSaltedAndRejectInvalidOrCorruptInputs() {
        val hasher = Pbkdf2PinHasher()
        val encoded = hasher.encode("001234")
        assertNotEquals(encoded, hasher.encode("001234"))
        assertTrue(hasher.matches("001234", encoded))
        assertTrue(hasher.matches("٠٠١٢٣٤", encoded))
        assertFalse(hasher.matches("001235", encoded))
        assertFalse(hasher.matches("001234", "corrupt"))
        assertFalse(hasher.matches("001234", "AA==:AA=="))
        assertFalse(hasher.isValidPin("123"))
        assertFalse(hasher.isValidPin("1234abc"))
        assertTrue(hasher.isValidPin("0000"))
    }

    @Test
    public fun normalizerAndValidatorHandleMultilingualDigitsAndComplexityRules() {
        assertEquals(
            "1234",
            PinNormalizer.normalize(
                rawValue = " ١٢٣٤٥٦ ",
                digitsOnly = true,
                maxLength = 4,
            ),
        )

        val strictValidator = PinValidator(
            config = PinPolicyConfig(
                minPinLength = 4,
                maxPinLength = 8,
                disallowRepeatedDigits = true,
                disallowSequentialDigits = true,
            ),
        )
        val repeatedStatus = strictValidator.validate("١١١١")
        assertFalse(repeatedStatus.isNotRepeated)
        assertFalse(repeatedStatus.isNotTrivial)
        assertFalse(repeatedStatus.isValid)

        val sequentialStatus = strictValidator.validate("1234")
        assertFalse(sequentialStatus.isNotSequential)
        assertFalse(sequentialStatus.isNotTrivial)
        assertFalse(sequentialStatus.isValid)

        val strongStatus = strictValidator.validate("2580", primaryPinForComparison = "1379")
        assertTrue(strongStatus.isNotTrivial)
        assertTrue(strongStatus.isDistinctFromPrimary)
        assertTrue(strongStatus.isValid)
    }

    @Test
    public fun managerSupportsMasterAndDuressPinsAndLockoutTracking() {
        var nowMillis = 1_000L
        val store = InMemoryAppLockStateStore()
        val manager = AppLockManager(
            stateStore = store,
            clock = { nowMillis },
            attemptTracker = AppLockAttemptTracker(
                policy = AppLockAttemptPolicy(maxAttempts = 2, lockoutMillis = 5_000L),
                clock = { nowMillis },
            ),
        )

        val setupResult = manager.configurePinCredentials(
            masterPin = "١٢٣٤",
            duressPin = "9999",
        )
        assertTrue(setupResult is PinConfigurationResult.Success)
        assertFalse(manager.isLocked())

        manager.lock()
        assertTrue(manager.isLocked())

        val duressOutcome = manager.evaluateCredential("9999")
        assertEquals(AppLockUnlockResult.DURESS, duressOutcome.result)
        assertEquals(AppLockGateMode.DECOY, duressOutcome.snapshot.gateMode)

        val masterOutcome = manager.evaluateCredential("1234")
        assertEquals(AppLockUnlockResult.MASTER, masterOutcome.result)
        assertEquals(AppLockGateMode.UNLOCKED, masterOutcome.snapshot.gateMode)

        manager.lock()
        assertEquals(AppLockUnlockResult.INVALID, manager.evaluateCredential("0000").result)
        assertEquals(AppLockUnlockResult.LOCKED_OUT, manager.evaluateCredential("0000").result)
        assertEquals(AppLockUnlockResult.LOCKED_OUT, manager.evaluateCredential("1234").result)

        nowMillis += 6_000L
        assertEquals(AppLockUnlockResult.MASTER, manager.evaluateCredential("1234").result)
    }

    @Test
    public fun legacySha256CredentialIsTransparentlyUpgradedToSaltedPbkdf2OnUnlock() {
        val legacyHash = AppLockHashing.sha256("2468")
        val store = InMemoryAppLockStateStore(
            initialPolicy = AppLockPolicy(
                enabled = true,
                protectionType = AppLockProtectionType.PIN,
                credentialHash = legacyHash,
                hashAlgorithm = CredentialHashAlgorithm.SHA_256,
            ),
        )
        val manager = AppLockManager(stateStore = store)

        val outcome = manager.evaluateCredential("٢٤٦٨")
        assertEquals(AppLockUnlockResult.MASTER, outcome.result)

        val upgradedPolicy = store.readPolicy()
        assertEquals(CredentialHashAlgorithm.PBKDF2_HMAC_SHA256, upgradedPolicy.hashAlgorithm)
        assertTrue(':' in upgradedPolicy.credentialHash)
        assertNotEquals(legacyHash, upgradedPolicy.credentialHash)
    }

    @Test
    public fun hmacIntegritySignerAndSecurityHooksEmitTamperDuressAndCriticalAlerts() {
        val signer = JvmHmacIntegritySigner("connecttag-test-secret-key-bytes".toByteArray(Charsets.UTF_8))
        val policyPayload = AppLockCanonicalSerializer.serializePolicy(AppLockPolicy(enabled = true))
        val signature = signer.sign(policyPayload)
        assertTrue(signer.verify(policyPayload, signature))
        assertFalse(
            signer.verify(
                AppLockCanonicalSerializer.serializePolicy(AppLockPolicy(enabled = false)),
                signature,
            ),
        )

        var nowMillis = 10_000L
        val store = InMemoryAppLockStateStore()
        val emittedEvents = mutableListOf<AppLockSecurityEvent>()
        val manager = AppLockManager(
            stateStore = store,
            clock = { nowMillis },
            attemptTracker = AppLockAttemptTracker(
                policy = AppLockAttemptPolicy(
                    maxAttempts = 2,
                    lockoutMillis = 1_000L,
                    criticalFailureThreshold = 2,
                ),
                clock = { nowMillis },
            ),
            initialSecurityHooks = listOf(AppLockSecurityHook { event -> emittedEvents += event }),
        )

        manager.configurePinCredentials(masterPin = "1357", duressPin = "8642")

        // Trigger panic lock via 3 rapid hardware key presses
        assertFalse(manager.onPanicTriggerKeyPressed())
        assertFalse(manager.onPanicTriggerKeyPressed())
        assertTrue(manager.onPanicTriggerKeyPressed())
        assertTrue(emittedEvents.any { it is AppLockSecurityEvent.PanicLockTriggered })

        // Trigger Duress event
        manager.evaluateCredential("8642")
        assertTrue(emittedEvents.any { it is AppLockSecurityEvent.DuressTriggered })

        // Unlock with Master, then lock and trigger critical failure threshold + tamper event
        manager.evaluateCredential("1357")
        manager.lock()
        store.simulateTamperDetected(true)
        assertEquals(AppLockGateMode.LOCKED, manager.resolveGateMode())

        manager.evaluateCredential("0000")
        assertTrue(emittedEvents.any { it is AppLockSecurityEvent.PolicyTamperDetected })

        manager.evaluateCredential("0000")
        assertTrue(emittedEvents.any { it is AppLockSecurityEvent.CriticalFailureThresholdReached })
    }
}
