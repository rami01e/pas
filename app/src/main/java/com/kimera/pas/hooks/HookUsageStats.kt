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
 * v2.12.13 USAGE-STATS FILTER.
 *
 * Root cause of the 2026-10-21 Snakzy leak (per-app log
 * "usage queryEvents: mStringPool null — passthrough"):
 *
 *   - v2.12.12 rebuilt UsageEvents via the hidden (List, String[]) ctor
 *     and refused to proceed when mStringPool was null.
 *   - On Android 15 / MuMu, queryEvents returns a UsageEvents whose events
 *     carry direct String package names and whose mStringPool is genuinely
 *     null, so the ctor path was always taken, always rejected, and the
 *     original object was returned unfiltered. Every hidden pkg leaked.
 *
 * v2.12.13 fix: mutate the returned UsageEvents in place. Set mEvents /
 * mEventCount / mIndex on the SAME object, leave mStringPool alone (null
 * or not). No ctor, no pool dependency, no re-parcel corruption.
 *
 * Surfaces covered:
 *   queryUsageStats(int, long, long)              -> List<UsageStats>
 *   queryAndAggregateUsageStats(long, long)       -> Map<String, UsageStats>
 *   queryEvents(long, long)                       -> UsageEvents
 *   queryEventsForSelf(long, long)                -> UsageEvents
 *   queryEventStats(int, long, long)              -> List<EventStats>
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
        runCatching { cls.getMethod("getPackageName").invoke(e) as? String }.getOrNull()
    }.getOrNull()

    // ------------------------------------------------------------------
    /**
     * Mutates `src` in place - no new UsageEvents, no ctor, no string pool.
     *
     * Why in-place, not rebuild:
     *  - Android 15 queryEvents returns UsageEvents with mStringPool == null
     *    when events carry direct String package names. The hidden
     *    (List, String[]) ctor requires a non-null pool on some builds and
     *    is fragile on others. In-place mutation sidesteps both.
     *  - getNextEvent() reads mEvents / mEventCount / mIndex only.
     *  - If the caller re-parcels the object, writeToParcel() on API 35 also
     *    reads mEvents / mEventCount / mStringPool - all already consistent
     *    because we filtered the exact list that was already there.
     *
     * Return contract:
     *  - null          -> caller returns the untouched result
     *  - src (mutated) -> caller returns src as the result (filtered)
     *  - src (unmutated, removed == 0) -> no-op, same as returning result
     */
    private fun filterEvents(
        module: XposedModule,
        src: UsageEvents,
        label: String
    ): UsageEvents? = runCatching {
        val cls = UsageEvents::class.java

        val fEvents = cls.getDeclaredField("mEvents").apply { isAccessible = true }
        val fEventsToWrite = runCatching {
            cls.getDeclaredField("mEventsToWrite").apply { isAccessible = true }
        }.getOrNull()
        val fEventCount = cls.getDeclaredField("mEventCount").apply { isAccessible = true }
        val fIndex = runCatching {
            cls.getDeclaredField("mIndex").apply { isAccessible = true }
        }.getOrNull()

        @Suppress("UNCHECKED_CAST")
        val readSide = fEvents.get(src) as? List<UsageEvents.Event>

        @Suppress("UNCHECKED_CAST")
        val writeSide = fEventsToWrite?.get(src) as? List<UsageEvents.Event>

        val source = readSide ?: writeSide ?: run {
            if (!eventsRebuildLogged) {
                eventsRebuildLogged = true
                module.log(Log.INFO, TAG, "[PAS] $label: no mEvents/mEventsToWrite — passthrough")
            }
            return@runCatching null
        }

        if (source.isEmpty()) return@runCatching src

        val kept = ArrayList<UsageEvents.Event>(source.size)
        var removed = 0
        for (e in source) {
            val pkg = runCatching { e.packageName }.getOrNull()
            if (pkg != null && SweepList.isHidden(pkg, hidden)) {
                removed++
                SweepList.logHit(module, label, pkg)
            } else {
                kept.add(e)
            }
        }
        if (removed == 0) return@runCatching src

        // Mutate the SAME object the framework gave us. This keeps every
        // other internal field (mStringPool, mParcel, whatever OEMs added)
        // exactly as the framework produced it.
        fEvents.set(src, kept)
        if (writeSide != null && fEventsToWrite != null) {
            fEventsToWrite.set(src, kept)
        }
        fEventCount.setInt(src, kept.size)
        fIndex?.setInt(src, 0)

        if (!eventsRebuildLogged) {
            eventsRebuildLogged = true
            module.log(Log.INFO, TAG,
                "[PAS] $label: filtered in place ($removed hidden, ${kept.size} kept)")
        }
        src
    }.onFailure {
        if (!eventsRebuildLogged) {
            eventsRebuildLogged = true
            module.log(Log.INFO, TAG,
                "[PAS] $label: passthrough (${it::class.simpleName}: ${it.message})")
        }
    }.getOrNull()
}