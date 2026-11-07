package org.connecttag.lib.features.applock

/**
 * Normalizes PIN and numeric credential inputs across different locales and keyboards.
 *
 * Number keyboards on Android devices configured with Arabic or Persian locales may emit
 * Arabic-Indic (`٠-٩`) or Eastern Arabic-Indic (`۰-۹`) digits. This normalizer converts all
 * Unicode decimal digits into canonical ASCII digits (`0-9`) before validation or hashing.
 */
public object PinNormalizer {
    private const val DECIMAL_RADIX: Int = 10
    private const val MIN_DIGIT: Int = 0
    private const val MAX_DIGIT: Int = 9
    private const val ASCII_ZERO_CODE: Int = '0'.code

    /**
     * Converts any Unicode decimal digit in [rawValue] to its canonical ASCII (`0-9`) representation.
     * Non-digit characters are preserved as-is unless [digitsOnly] is enabled.
     * If [maxLength] is provided, the resulting string is truncated to at most [maxLength] characters.
     */
    public fun normalize(
        rawValue: String,
        trimWhitespace: Boolean = true,
        digitsOnly: Boolean = false,
        maxLength: Int? = null,
    ): String {
        require(maxLength == null || maxLength >= 0) {
            "maxLength ($maxLength) must be non-negative"
        }
        if (maxLength == 0) return ""
        val source = if (trimWhitespace) rawValue.trim() else rawValue
        if (source.isEmpty()) return ""

        val builder = StringBuilder(source.length)
        for (character in source) {
            val numericValue = Character.digit(character, DECIMAL_RADIX)
            when {
                numericValue in MIN_DIGIT..MAX_DIGIT -> {
                    builder.append((ASCII_ZERO_CODE + numericValue).toChar())
                }
                !digitsOnly -> {
                    builder.append(character)
                }
            }
            if (maxLength != null && builder.length >= maxLength) {
                break
            }
        }
        return builder.toString()
    }

    /**
     * Returns `true` if every character in [rawValue] (after optional trimming) is a decimal digit.
     */
    public fun isNumericOnly(rawValue: String): Boolean {
        val normalized = normalize(rawValue)
        return normalized.isNotEmpty() && normalized.all { char -> char in '0'..'9' }
    }
}
