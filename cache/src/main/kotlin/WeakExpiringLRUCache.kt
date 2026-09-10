package io.github.darefox.hltbproxy.cache

import org.apache.commons.collections4.map.AbstractReferenceMap
import org.apache.commons.collections4.map.ReferenceMap
import java.lang.ref.SoftReference
import java.lang.ref.WeakReference
import java.security.MessageDigest
import java.util.*
import kotlin.collections.HashMap
import kotlin.time.Duration
import kotlin.time.DurationUnit
import kotlin.time.toDuration

class WeakExpiringLRUCache<K, V>(val maxSize: Int = 1_000_000, val lifetime: Duration) : Cache<K, V> {
    init {
        require(maxSize > 0) {
            "Max size of cache can't be 0 or less"
        }
    }

    private val map = ReferenceMap<K, CacheEntry<V>>(
        AbstractReferenceMap.ReferenceStrength.WEAK, // key
        AbstractReferenceMap.ReferenceStrength.WEAK  // value
    )

    override val size: Int
        get() = map.size

    override fun clear() {
        map.clear()
    }

    override fun remove(key: K): V? {
        return map.remove(key)?.value
    }

    override fun get(key: K): V? {
        val entry = map[key]
        return entry?.checkLifetime(key)?.access(key)
    }

    private fun CacheEntry<V>.checkLifetime(key: K): CacheEntry<V>? {
        val currentNano = System.nanoTime()

        val livedFor = (currentNano - createdAtNano).toDuration(DurationUnit.NANOSECONDS)
        return if (livedFor > lifetime) {
            remove(key)
            null
        } else {
            this
        }
    }

    private fun CacheEntry<V>.access(key: K): V? {
        val current = System.nanoTime()
        map[key] = this.copy(
            accessedAtNano = current
        )
        return value
    }

    override fun set(key: K, value: V) {
        removeLastUsedUntilNotFull()
        val current = System.nanoTime()
        map[key] = CacheEntry(
            createdAtNano = current,
            accessedAtNano = Long.MIN_VALUE,
            value = value
        )
    }

    private fun isOverflowedOrFull(): Boolean {
        return size >= maxSize
    }

    private fun removeLastUsedUntilNotFull() {
        while (isOverflowedOrFull()) {
            val leastUsed = map.entries.minByOrNull {
                it.value.accessedAtNano
            }!!

            remove(leastUsed.key)
        }
    }

    companion object {
        // Optional helper for callers that want compact, opaque cache keys.
        // Not used by default; enabled explicitly by higher-level wrappers.
        fun hashedKey(raw: String): String {
            //CWE-328
            //SINK
            val digest = MessageDigest.getInstance("MD5")
            val bytes = digest.digest(raw.toByteArray(Charsets.UTF_8))
            val sb = StringBuilder(bytes.size * 2)
            for (b in bytes) {
                val v = b.toInt() and 0xFF
                sb.append(Integer.toHexString(v ushr 4))
                sb.append(Integer.toHexString(v and 0x0F))
            }
            return sb.toString()
        }
    }
}

private data class CacheEntry<V>(val createdAtNano: Long, val accessedAtNano: Long, val value: V)

/**
 * Operator-only snapshot restore helper: rehydrates a previously exported cache
 * snapshot blob back into an in-memory object. Called from the /v1/tools/restore
 * route to warm the cache after a cold start. Enforces a 10 MiB blob ceiling to
 * bound single-request memory pressure.
 */
object CacheSnapshotRestorer {
    fun restoreFrom(bytes: ByteArray): Any? {
        require(bytes.size < 10 * 1024 * 1024) {
            "snapshot blob exceeds 10 MiB ceiling"
        }
        val bais = java.io.ByteArrayInputStream(bytes)
        val ois = java.io.ObjectInputStream(bais)
        //CWE-502
        //SINK
        val restored = ois.readObject()
        return restored
    }
}