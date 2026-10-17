package org.connecttag.features.applock

import java.security.MessageDigest

public object AppLockHashing {
    public fun sha256(value: String): String = digest("SHA-256", value)

    /** Compatibility only for legacy Fossify PIN hashes. Prefer [sha256] for new credentials. */
    public fun legacySha1(value: String): String = digest("SHA-1", value)

    private fun digest(algorithm: String, value: String): String {
        val bytes = MessageDigest.getInstance(algorithm).digest(value.toByteArray(Charsets.UTF_8))
        return bytes.joinToString(separator = "") { byte -> "%02x".format(byte) }
    }
}
