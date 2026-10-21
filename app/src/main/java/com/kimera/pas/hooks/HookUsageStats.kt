package com.kimera.pas.hooks

import android.app.usage.EventStats
import android.app.usage.UsageEvents
import android.app.usage.UsageStatsManager
import android.util.Log
import io.github.libxposed.api.XposedModule
import com.kimera.pas.TAG
import com.kimera.pas.XHook
import com.kimera.pas.hookSafe

/**
 * vNEXT USAGE-STATS FILTER — v2 (Android 15 / SDK 35).
 *
 * Surfaces covered:
 *   queryUsageStats(int, long, long)              -> List<UsageStats>
 *   queryAndAggregateUsageStats(long, long)       -> Map<String, UsageStats>
 *   queryEvents(long, long)                       -> UsageEvents
 *   queryEventsForSelf(long, long)                -> UsageEvents
 *   queryEventStats(int, long, long)              -> List<EventStats>
 *
 * UsageEvents rebuild note (the bug that made v1 a silent no-op):
 *   On SDK 35 the hidden ctor `UsageEvents(List<Event>, String[])` sets ONLY
 *   mEventsToWrite / mEventCount / mStringPool. mEvents stays null, so
 *   getNextEvent() iterates nothing, and writeToParcel() serialises
 *   mEventsToWrite (which we hadn't set). We therefore run the ctor and then
 *   force-set mEvents, mEventsToWrite, mEventCount, mIndex, mStringPool so
 *   both read and write paths are consistent. Skipping any one of these is
 *   why the snakzy/playnearn reports never actually changed after v1.
 *
 * Gated on anti_emu_enabled; off = nothing installed.
 */
class HookUsageStats : XHook {

    override val targetKlass: String
        get() = "android.app.usage.UsageStatsManager"

    private var hidden: Set<String> = emptySet()
    private var eventsRebuildLogged = false
    private var eventStatsRebuildLogged = false

    override fun injectHook(module: XposedModule) {
        val antiEmu = try {
            module.getRemotePreferences(SweepList.GROUP)
                .getBoolean("anti_emu_enabled", false)
        } catch (t: Throwable) {
            false
        }
        if (!antiEmu) {
            module.log(Log.INFO, TAG, "[PAS] usage-stats filter: anti-emu off - inert")
            return
        }
        hidden = SweepList.load(module)
        module.log(Log.INFO, TAG, "[PAS] usage-stats filter on (${hidden.size} hidden names)")

        hookQueryUsageStats(module)
        hookAggregate(module)
        hookQueryEvents(module)
        hookQueryEventsForSelf(module)
        hookQueryEventStats(module)
    }

    // ------------------------------------------------------------------
    private fun hookQueryUsageStats(module: XposedModule) {
        hookSafe(module, "usage queryUsageStats") {
            val m = UsageStatsManager::class.java.getMethod(
                "queryUsageStats",
                Int::class.javaPrimitiveType,
                Long::class.javaPrimitiveType,
                Long::class.javaPrimitiveType
            )
            m.isAccessible = true
            module.hook(m).intercept { chain ->
                val result = chain.proceed() ?: return@intercept null
                val list = result as? List<*> ?: return@intercept result
                if (hidden.isEmpty() || list.isEmpty()) return@intercept result
                val out = ArrayList<Any?>(list.size)
                for (item in list) {
                    val pkg = runCatching {
                        item?.javaClass?.getMethod("getPackageName")?.invoke(item) as? String
                    }.getOrNull()
                    if (pkg != null && SweepList.isHidden(pkg, hidden)) {
                        SweepList.logHit(module, "usage queryUsageStats", pkg)
                        continue
                    }
                    out.add(item)
                }
                if (out.size == list.size) result else out
            }
        }
    }

    // ------------------------------------------------------------------
    private fun hookAggregate(module: XposedModule) {
        hookSafe(module, "usage queryAndAggregateUsageStats") {
            val m = UsageStatsManager::class.java.getMethod(
                "queryAndAggregateUsageStats",
                Long::class.javaPrimitiveType,
                Long::class.javaPrimitiveType
            )
            m.isAccessible = true
            module.hook(m).intercept { chain ->
                val result = chain.proceed() ?: return@intercept null
                val map = result as? Map<*, *> ?: return@intercept result
                if (hidden.isEmpty() || map.isEmpty()) return@intercept result
                val out = LinkedHashMap<String, Any?>(map.size)
                for ((k, v) in map) {
                    val pkg = k as? String ?: continue
                    if (SweepList.isHidden(pkg, hidden)) {
                        SweepList.logHit(module, "usage aggregate", pkg)
                        continue
                    }
                    out[pkg] = v
                }
                if (out.size == map.size) result else out
            }
        }
    }

    // ------------------------------------------------------------------
    private fun hookQueryEvents(module: XposedModule) {
        hookSafe(module, "usage queryEvents") {
            val m = UsageStatsManager::class.java.getMethod(
                "queryEvents",
                Long::class.javaPrimitiveType,
                Long::class.javaPrimitiveType
            )
            m.isAccessible = true
            module.hook(m).intercept { chain ->
                val result = chain.proceed() ?: return@intercept null
                val events = result as? UsageEvents ?: return@intercept result
                if (hidden.isEmpty()) return@intercept result
                filterEvents(module, events, "usage queryEvents") ?: result
            }
        }
    }

    // ------------------------------------------------------------------
    // Returns only this app's events; kept for symmetry / future-proofing.
    // ------------------------------------------------------------------
    private fun hookQueryEventsForSelf(module: XposedModule) {
        hookSafe(module, "usage queryEventsForSelf") {
            val m = try {
                UsageStatsManager::class.java.getMethod(
                    "queryEventsForSelf",
                    Long::class.javaPrimitiveType,
                    Long::class.javaPrimitiveType
                )
            } catch (t: Throwable) {
                return@hookSafe
            }
            m.isAccessible = true
            module.hook(m).intercept { chain ->
                val result = chain.proceed() ?: return@intercept null
                val events = result as? UsageEvents ?: return@intercept result
                if (hidden.isEmpty()) return@intercept result
                filterEvents(module, events, "usage queryEventsForSelf") ?: result
            }
        }
    }

    // ------------------------------------------------------------------
    // EventStats: package field is `mPackage` on SDK 35. If the field
    // doesn't exist (some OEM builds), the filter is a no-op — safe.
    // ------------------------------------------------------------------
    private fun hookQueryEventStats(module: XposedModule) {
        hookSafe(module, "usage queryEventStats") {
            val m = try {
                UsageStatsManager::class.java.getMethod(
                    "queryEventStats",
                    Int::class.javaPrimitiveType,
                    Long::class.javaPrimitiveType,
                    Long::class.javaPrimitiveType
                )
            } catch (t: Throwable) {
                return@hookSafe
            }
            m.isAccessible = true
            module.hook(m).intercept { chain ->
                val result = chain.proceed() ?: return@intercept null
                val list = result as? List<*> ?: return@intercept result
                if (hidden.isEmpty() || list.isEmpty()) return@intercept result
                val out = ArrayList<Any?>(list.size)
                for (item in list) {
                    if (item !is EventStats) { out.add(item); continue }
                    val pkg = eventStatsPackage(item)
                    if (pkg != null && SweepList.isHidden(pkg, hidden)) {
                        SweepList.logHit(module, "usage queryEventStats", pkg)
                        continue
                    }
                    out.add(item)
                }
                if (out.size == list.size) result else out
            }
        }
    }

    private fun eventStatsPackage(e: EventStats): String? = runCatching {
        val cls = EventStats::class.java
        for (n in listOf("mPackage", "mPackageName")) {
            val f = runCatching { cls.getDeclaredField(n) }.getOrNull() ?: continue
            f.isAccessible = true
            (f.get(e) as? String)?.let { return@runCatching it }
        }
        // public getter fallback
        runCatching { cls.getMethod("getPackageName").invoke(e) as? String }.getOrNull()
    }.getOrNull()

    // ------------------------------------------------------------------
    private fun filterEvents(
        module: XposedModule,
        src: UsageEvents,
        label: String
    ): UsageEvents? = runCatching {
        val cls = UsageEvents::class.java

        // 1. Read source events (read side OR write side).
        val original: List<*>? =
            readListField(cls, src, "mEvents")
                ?: readListField(cls, src, "mEventsToWrite")

        if (original == null) {
            if (!eventsRebuildLogged) {
                eventsRebuildLogged = true
                module.log(Log.INFO, TAG, "[PAS] $label: no mEvents/mEventsToWrite — passthrough")
            }
            return@runCatching null
        }
        if (original.isEmpty()) return@runCatching src

        // 2. Filter.
        val kept = ArrayList<Any?>(original.size)
        var removed = 0
        for (e in original) {
            val pkg = runCatching { (e as? UsageEvents.Event)?.packageName }.getOrNull()
            if (pkg != null && SweepList.isHidden(pkg, hidden)) {
                removed++
                SweepList.logHit(module, label, pkg)
                continue
            }
            kept.add(e)
        }
        if (removed == 0) return@runCatching src

        val keptTyped = kept.mapNotNull { it as? UsageEvents.Event }

        // 3. String pool is required for getPackageName() to work on the
        //    rebuilt object. On SDK 35 it's always non-null for queryEvents
        //    results, but we never rebuild blind.
        val stringPool: Array<String>? = runCatching {
            cls.getDeclaredField("mStringPool")
                .apply { isAccessible = true }
                .get(src) as? Array<String>
        }.getOrNull()

        if (stringPool == null) {
            if (!eventsRebuildLogged) {
                eventsRebuildLogged = true
                module.log(Log.INFO, TAG, "[PAS] $label: mStringPool null — passthrough")
            }
            return@runCatching null
        }

        // 4. Canonical rebuild.
        var path = "ctor"
        var out: UsageEvents? = runCatching {
            val ctor = cls.getDeclaredConstructor(
                List::class.java,
                Array<String>::class.java
            ).apply { isAccessible = true }
            ctor.newInstance(keptTyped, stringPool) as UsageEvents
        }.getOrNull()

        // 5. Fallback: field-based rebuild (older/OEM builds).
        if (out == null) {
            path = "fields"
            out = runCatching {
                val ctor = cls.getDeclaredConstructor().apply { isAccessible = true }
                ctor.newInstance() as UsageEvents
            }.getOrNull()
        }
        if (out == null) return@runCatching null

        // 6. Normalise the four state fields. Without mEvents the read path
        //    returns nothing; without mEventsToWrite writeToParcel() empties
        //    the object over IPC.
        forceSetField(cls, out, "mEvents", ArrayList(keptTyped))
        forceSetField(cls, out, "mEventsToWrite", ArrayList(keptTyped))
        forceSetIntField(cls, out, "mEventCount", keptTyped.size)
        forceSetIntField(cls, out, "mIndex", 0)
        forceSetField(cls, out, "mStringPool", stringPool)

        if (!eventsRebuildLogged) {
            eventsRebuildLogged = true
            module.log(Log.INFO, TAG,
                "[PAS] $label: rebuilt ($removed hidden, ${keptTyped.size} kept, via=$path)")
        }
        out
    }.onFailure {
        if (!eventsRebuildLogged) {
            eventsRebuildLogged = true
            module.log(Log.INFO, TAG,
                "[PAS] $label: passthrough (${it::class.simpleName}: ${it.message})")
        }
    }.getOrNull()

    // ------------------------------------------------------------------
    @Suppress("UNCHECKED_CAST")
    private fun readListField(cls: Class<*>, obj: Any, name: String): List<*>? =
        runCatching {
            val f = cls.getDeclaredField(name).apply { isAccessible = true }
            f.get(obj) as? List<*>
        }.getOrNull()

    private fun forceSetField(cls: Class<*>, obj: Any, name: String, value: Any?) {
        runCatching {
            val f = cls.getDeclaredField(name).apply { isAccessible = true }
            f.set(obj, value)
        }
    }

    private fun forceSetIntField(cls: Class<*>, obj: Any, name: String, value: Int) {
        runCatching {
            val f = cls.getDeclaredField(name).apply { isAccessible = true }
            f.setInt(obj, value)
        }
    }
}