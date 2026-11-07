package org.connecttag.lib.features.applock

import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

/**
 * Contract for encoding and verifying PIN/credential secrets.
 */
public interface PinHasher {
    /**
     * Encodes [rawPin] into a salted or hashed representation suitable for persistent storage.
     */
    public fun encode(rawPin: String): String

    /**
     * Verifies whether [rawPin] matches the previously [encodedHash] in constant time.
     */
    public fun matches(rawPin: String, encodedHash: String): Boolean

    /**
     * Returns `true` if [encodedHash] uses a legacy format or weaker iteration count and should be re-encoded.
     */
    public fun needsRehash(encodedHash: String): Boolean = false
}

/**
 * Production-grade PBKDF2-HMAC-SHA256 PIN hasher with per-PIN cryptographic salt and
 * constant-time comparison (`MessageDigest.isEqual`).
 *
 * Compatible with both the compact `<base64Salt>:<base64Digest>` format from `com.protection.connected`
 * and the parameterized `pbkdf2_sha256$<iterations>$<base64Salt>$<base64Digest>` format.
 */
public class Pbkdf2PinHasher(
    private val validator: PinValidator = PinValidator(),
    private val iterations: Int = DEFAULT_ITERATIONS,
    private val saltLengthBytes: Int = DEFAULT_SALT_BYTES,
    private val keyLengthBits: Int = DEFAULT_KEY_BITS,
    private val secureRandom: SecureRandom = SecureRandom(),
) : PinHasher {

    init {
        require(iterations >= MIN_ITERATIONS) {
            "PBKDF2 iterations ($iterations) must be at least $MIN_ITERATIONS"
        }
        require(saltLengthBytes >= MIN_SALT_BYTES) {
            "PBKDF2 salt length ($saltLengthBytes) must be at least $MIN_SALT_BYTES bytes"
        }
        require(keyLengthBits >= MIN_KEY_BITS && keyLengthBits % BITS_PER_BYTE == 0) {
            "PBKDF2 key length ($keyLengthBits) must be a multiple of 8 and at least $MIN_KEY_BITS bits"
        }
    }

    public fun isValidPin(rawPin: String): Boolean = validator.isValidPin(rawPin)

    override fun encode(rawPin: String): String {
        val normalized = PinNormalizer.normalize(rawPin)
        require(validator.isValidPin(normalized)) {
            "PIN does not satisfy the configured PinPolicyConfig"
        }
        val salt = ByteArray(saltLengthBytes).also(secureRandom::nextBytes)
        val digest = derive(normalized, salt, iterations, keyLengthBits)
        val encoder = Base64.getEncoder()
        return buildString {
            append(encoder.encodeToString(salt))
            append(COMPACT_DELIMITER)
            append(encoder.encodeToString(digest))
        }
    }

    /**
     * Encodes [rawPin] using the explicit versioned format `pbkdf2_sha256$<iterations>$<salt>$<digest>`.
     */
    public fun encodeVersioned(rawPin: String): String {
        val normalized = PinNormalizer.normalize(rawPin)
        require(validator.isValidPin(normalized)) {
            "PIN does not satisfy the configured PinPolicyConfig"
        }
        val salt = ByteArray(saltLengthBytes).also(secureRandom::nextBytes)
        val digest = derive(normalized, salt, iterations, keyLengthBits)
        val encoder = Base64.getEncoder()
        return listOf(
            VERSIONED_PREFIX,
            iterations.toString(),
            encoder.encodeToString(salt),
            encoder.encodeToString(digest),
        ).joinToString(separator = VERSIONED_DELIMITER.toString())
    }

    override fun matches(rawPin: String, encodedHash: String): Boolean {
        val normalized = PinNormalizer.normalize(rawPin)
        if (!validator.isValidPin(normalized) || encodedHash.isBlank()) return false

        return runCatching {
            val parsed = parseEncodedHash(encodedHash) ?: return false
            val actualDigest = derive(
                pin = normalized,
                salt = parsed.salt,
                iterationCount = parsed.iterations,
                derivedKeyBits = parsed.expectedDigest.size * BITS_PER_BYTE,
            )
            MessageDigest.isEqual(parsed.expectedDigest, actualDigest)
        }.getOrDefault(false)
    }

    override fun needsRehash(encodedHash: String): Boolean {
        val parsed = runCatching { parseEncodedHash(encodedHash) }.getOrNull() ?: return true
        return parsed.iterations < iterations || parsed.salt.size < saltLengthBytes
    }

    private fun parseEncodedHash(encoded: String): ParsedPbkdf2Hash? {
        val decoder = Base64.getDecoder()
        if (encoded.startsWith("$VERSIONED_PREFIX$VERSIONED_DELIMITER")) {
            val parts = encoded.split(VERSIONED_DELIMITER)
            if (parts.size != VERSIONED_PART_COUNT) return null
            val parsedIterations = parts[1].toIntOrNull()?.takeIf { it >= MIN_ITERATIONS } ?: return null
            val salt = decoder.decode(parts[2])
            val expected = decoder.decode(parts[3])
            if (salt.size < MIN_SALT_BYTES || expected.size < MIN_KEY_BITS / BITS_PER_BYTE) return null
            return ParsedPbkdf2Hash(
                iterations = parsedIterations,
                salt = salt,
                expectedDigest = expected,
            )
        }

        val compactParts = encoded.split(COMPACT_DELIMITER)
        if (compactParts.size != COMPACT_PART_COUNT) return null
        val salt = decoder.decode(compactParts[0])
        val expected = decoder.decode(compactParts[1])
        val expectedByteSize = keyLengthBits / BITS_PER_BYTE
        if (salt.size != saltLengthBytes || expected.size != expectedByteSize) return null
        return ParsedPbkdf2Hash(
            iterations = iterations,
            salt = salt,
            expectedDigest = expected,
        )
    }

    private fun derive(
        pin: String,
        salt: ByteArray,
        iterationCount: Int,
        derivedKeyBits: Int,
    ): ByteArray {
        val keySpec = PBEKeySpec(pin.toCharArray(), salt, iterationCount, derivedKeyBits)
        return try {
            SecretKeyFactory.getInstance(PBKDF2_ALGORITHM).generateSecret(keySpec).encoded
        } finally {
            keySpec.clearPassword()
        }
    }

    private class ParsedPbkdf2Hash(
        val iterations: Int,
        val salt: ByteArray,
        val expectedDigest: ByteArray,
    )

    public companion object {
        public const val PBKDF2_ALGORITHM: String = "PBKDF2WithHmacSHA256"
        public const val DEFAULT_ITERATIONS: Int = 120_000
        public const val MIN_ITERATIONS: Int = 10_000
        public const val DEFAULT_SALT_BYTES: Int = 16
        public const val MIN_SALT_BYTES: Int = 8
        public const val DEFAULT_KEY_BITS: Int = 256
        public const val MIN_KEY_BITS: Int = 128

        private const val BITS_PER_BYTE: Int = 8
        private const val COMPACT_DELIMITER: Char = ':'
        private const val COMPACT_PART_COUNT: Int = 2
        private const val VERSIONED_PREFIX: String = "pbkdf2_sha256"
        private const val VERSIONED_DELIMITER: Char = '$'
        private const val VERSIONED_PART_COUNT: Int = 4
    }
}

/**
 * Hashing helper facade supporting modern salted PBKDF2-HMAC-SHA256 alongside legacy unsalted digests.
 */
public object AppLockHashing {
    private const val SHA_256_ALGORITHM: String = "SHA-256"
    private const val SHA_1_ALGORITHM: String = "SHA-1"
    private const val HEX_BYTE_FORMAT: String = "%02x"

    private val defaultPbkdf2Hasher: Pbkdf2PinHasher = Pbkdf2PinHasher(
        validator = PinValidator(
            PinPolicyConfig(
                minPinLength = 1,
                maxPinLength = 128,
                digitsOnly = false,
            ),
        ),
    )

    /**
     * Generates a salted `PBKDF2WithHmacSHA256` hash (`<base64Salt>:<base64Digest>`).
     */
    public fun pbkdf2Sha256(value: String): String =
        defaultPbkdf2Hasher.encode(PinNormalizer.normalize(value))

    /**
     * Unsalted SHA-256 hex digest. Prefer [pbkdf2Sha256] for new PIN credentials.
     */
    public fun sha256(value: String): String =
        digest(SHA_256_ALGORITHM, PinNormalizer.normalize(value))

    /**
     * Compatibility only for legacy Fossify PIN hashes. Prefer [pbkdf2Sha256] or [sha256] for new credentials.
     */
    public fun legacySha1(value: String): String =
        digest(SHA_1_ALGORITHM, PinNormalizer.normalize(value))

    /**
     * Encodes [rawCredential] using the requested [algorithm].
     */
    public fun encode(
        rawCredential: String,
        algorithm: CredentialHashAlgorithm = CredentialHashAlgorithm.PBKDF2_HMAC_SHA256,
    ): String = when (algorithm) {
        CredentialHashAlgorithm.PBKDF2_HMAC_SHA256 -> pbkdf2Sha256(rawCredential)
        CredentialHashAlgorithm.SHA_256 -> sha256(rawCredential)
        CredentialHashAlgorithm.LEGACY_SHA_1 -> legacySha1(rawCredential)
    }

    /**
     * Verifies [rawCredential] against [storedHash] using constant-time comparison.
     * Automatically detects salted PBKDF2 hashes (`:` or `pbkdf2_sha256$`) even if [algorithm] was set to SHA_256.
     */
    public fun verify(
        rawCredential: String,
        storedHash: String,
        algorithm: CredentialHashAlgorithm = CredentialHashAlgorithm.PBKDF2_HMAC_SHA256,
    ): Boolean {
        if (storedHash.isBlank()) return false
        val normalized = PinNormalizer.normalize(rawCredential)
        if (normalized.isEmpty()) return false

        val isSaltedPbkdf2Format = ':' in storedHash || storedHash.startsWith("pbkdf2_sha256$")
        return when {
            isSaltedPbkdf2Format || algorithm == CredentialHashAlgorithm.PBKDF2_HMAC_SHA256 -> {
                if (isSaltedPbkdf2Format) {
                    defaultPbkdf2Hasher.matches(normalized, storedHash)
                } else {
                    constantTimeHexEquals(sha256(normalized), storedHash)
                }
            }
            algorithm == CredentialHashAlgorithm.SHA_256 -> {
                constantTimeHexEquals(sha256(normalized), storedHash)
            }
            algorithm == CredentialHashAlgorithm.LEGACY_SHA_1 -> {
                constantTimeHexEquals(legacySha1(normalized), storedHash)
            }
            else -> false
        }
    }

    private fun constantTimeHexEquals(actualHex: String, expectedHex: String): Boolean {
        val actualBytes = actualHex.lowercase().toByteArray(Charsets.UTF_8)
        val expectedBytes = expectedHex.lowercase().toByteArray(Charsets.UTF_8)
        return MessageDigest.isEqual(actualBytes, expectedBytes)
    }

    private fun digest(algorithm: String, value: String): String {
        val bytes = MessageDigest.getInstance(algorithm).digest(value.toByteArray(Charsets.UTF_8))
        return bytes.joinToString(separator = "") { byte -> HEX_BYTE_FORMAT.format(byte) }
    }
}
