package org.connecttag.lib.features.applock

/**
 * Configuration for validating PIN credentials, supporting extensible security policies.
 */
public data class PinPolicyConfig(
    public val minPinLength: Int = DEFAULT_MIN_PIN_LENGTH,
    public val maxPinLength: Int = DEFAULT_MAX_PIN_LENGTH,
    public val digitsOnly: Boolean = true,
    public val disallowRepeatedDigits: Boolean = false,
    public val disallowSequentialDigits: Boolean = false,
    public val requireDistinctDuressPin: Boolean = true,
) {
    init {
        require(minPinLength >= ABSOLUTE_MIN_PIN_LENGTH) {
            "minPinLength must be at least $ABSOLUTE_MIN_PIN_LENGTH"
        }
        require(maxPinLength >= minPinLength) {
            "maxPinLength ($maxPinLength) must be greater than or equal to minPinLength ($minPinLength)"
        }
    }

    public companion object {
        public const val ABSOLUTE_MIN_PIN_LENGTH: Int = 1
        public const val DEFAULT_MIN_PIN_LENGTH: Int = 4
        public const val DEFAULT_MAX_PIN_LENGTH: Int = 12
    }
}

/**
 * Extensible functional interface allowing consuming apps to register custom PIN rules.
 */
public fun interface PinRuleEvaluator {
    /**
     * Evaluates the normalized [candidatePin] and returns a non-null rule identifier if violated,
     * or `null` if the rule is satisfied.
     */
    public fun evaluateViolation(candidatePin: String): String?
}

/**
 * Detailed validation snapshot for a single PIN or a Master/Duress PIN pair.
 */
public data class PinValidationStatus(
    public val normalizedPin: String,
    public val isLengthValid: Boolean,
    public val isFormatValid: Boolean,
    public val isNotRepeated: Boolean = true,
    public val isNotSequential: Boolean = true,
    public val isDistinctFromPrimary: Boolean = true,
    public val customViolations: List<String> = emptyList(),
) {
    /**
     * Returns `true` when the PIN is neither a repeated-digit sequence nor a sequential pattern.
     */
    public val isNotTrivial: Boolean
        get() = isNotRepeated && isNotSequential

    /**
     * Returns `true` when all active policy rules and custom evaluators are satisfied.
     */
    public val isValid: Boolean
        get() = isLengthValid &&
            isFormatValid &&
            isNotRepeated &&
            isNotSequential &&
            isDistinctFromPrimary &&
            customViolations.isEmpty()
}

/**
 * Flexible PIN validator supporting length, character set, pattern complexity,
 * Master/Duress uniqueness, and custom [PinRuleEvaluator] plugins.
 */
public class PinValidator(
    public val config: PinPolicyConfig = PinPolicyConfig(),
    private val customEvaluators: List<PinRuleEvaluator> = emptyList(),
) {
    /**
     * Quick check returning `true` if [rawPin] satisfies all configured rules.
     */
    public fun isValidPin(
        rawPin: String,
        primaryPinForComparison: String? = null,
    ): Boolean = validate(rawPin, primaryPinForComparison).isValid

    /**
     * Evaluates [rawPin] and returns a detailed [PinValidationStatus] suitable for reactive UI feedback.
     */
    public fun validate(
        rawPin: String,
        primaryPinForComparison: String? = null,
    ): PinValidationStatus {
        val normalized = PinNormalizer.normalize(rawPin)
        val normalizedPrimary = primaryPinForComparison?.let { PinNormalizer.normalize(it) }

        val lengthValid = normalized.length in config.minPinLength..config.maxPinLength
        val formatValid = if (config.digitsOnly) {
            normalized.isNotEmpty() && normalized.all { char -> char in '0'..'9' }
        } else {
            normalized.isNotBlank()
        }

        val notRepeated = if (config.disallowRepeatedDigits && normalized.length > 1) {
            normalized.any { char -> char != normalized.first() }
        } else {
            true
        }

        val notSequential = if (config.disallowSequentialDigits && normalized.length >= MIN_SEQUENTIAL_CHECK_LENGTH) {
            !isSequentialAsciiDigits(normalized)
        } else {
            true
        }

        val distinctFromPrimary = if (config.requireDistinctDuressPin && !normalizedPrimary.isNullOrEmpty()) {
            normalized.isNotEmpty() && normalized != normalizedPrimary
        } else {
            true
        }

        val violations = if (normalized.isEmpty()) {
            emptyList()
        } else {
            customEvaluators.mapNotNull { evaluator -> evaluator.evaluateViolation(normalized) }
        }

        return PinValidationStatus(
            normalizedPin = normalized,
            isLengthValid = lengthValid,
            isFormatValid = formatValid,
            isNotRepeated = notRepeated,
            isNotSequential = notSequential,
            isDistinctFromPrimary = distinctFromPrimary,
            customViolations = violations,
        )
    }

    private fun isSequentialAsciiDigits(value: String): Boolean {
        if (!value.all { char -> char in '0'..'9' }) return false
        var ascending = true
        var descending = true
        for (index in 1 until value.length) {
            val diff = value[index].code - value[index - 1].code
            if (diff != 1) ascending = false
            if (diff != -1) descending = false
        }
        return ascending || descending
    }

    public companion object {
        private const val MIN_SEQUENTIAL_CHECK_LENGTH: Int = 3
    }
}
