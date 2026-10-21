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
 * v2.12.14 USAGE-STATS FILTER.
 *
 * Root cause chased through v2.12.12 -> v2.12.13 -> v2.12.14:
 *
 *   v2.12.12: read mEvents ?: mEventsToWrite via runCatching helper. On MuMu
 *             SDK 35, mEvents is ABSENT, so fallback to mEventsToWrite
 *             succeeded - but then mStringPool was null, so it bailed with
 *             "mStringPool null - passthrough". Result: unfiltered leak.
 *
 *   v2.12.13: hard getDeclaredField("mEvents"). On MuMu SDK 35 the field
 *             does not exist, so the call threw NoSuchFieldException and
 *             the whole filter was a passthrough. Result: unfiltered leak.
 *
 *   v2.12.14: (a) discover the events field by probing candidates and, as a
 *             last resort, by scanning declared fields for List<Event>;
 *             (b) mutate that field in place, update mEventCount and reset
 *             mIndex, never touch mStringPool; (c) belt-and-braces hook
 *             getNextEvent(Event) and getNextEventOrNull() so callers that
 *             iterate via the public API are filtered on the fly even if
 *             no field can be touched; (d) log the actual declared fields
 *             of UsageEvents once per process for future diagnosis.
 *
 * Surfaces covered:
 *   queryUsageStats(int, long, long)              -> List<UsageStats>
 *   queryAndAggregateUsageStats(long, long)       -> Map<String, UsageStats>
 *   queryEvents(long, long)                       -> UsageEvents
 *   queryEventsForSelf(long, long)                -> UsageEvents
 *   queryEventStats(int, long, long)              -> List<EventStats>
 *   UsageEvents.getNextEvent(Event)               -> Boolean
 *   UsageEvents.getNextEventOrNull()              -> Event?  (API 33+)
 *
 * Gated on anti_emu_enabled; off = nothing installed.
 */
class HookUsageStats : XHook {

    override val targetKlass: String
        get() = "android.app.usage.UsageStatsManager"

    private var hidden: Set<String> = emptySet()
    private var eventsRebuildLogged = false
    private var fieldsLogged = false
    private var getNextEventLogged = false

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
        hookGetNextEvent(module)
        hookGetNextEventOrNull(module)
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
     * Belt-and-braces: filter at the public iteration API. Works no matter
     * what internal field names the OEM used, as long as the caller uses
     * the documented getNextEvent pattern. Zero overhead when filterEvents
     * already mutated the underlying list - the events we see will not
     * match isHidden() and we return on the first proceed().
     */
    private fun hookGetNextEvent(module: XposedModule) {
        hookSafe(module, "usage getNextEvent") {
            val m = try {
                UsageEvents::class.java.getMethod(
                    "getNextEvent",
                    UsageEvents.Event::class.java
                )
            } catch (t: Throwable) {
                return@hookSafe
            }
            m.isAccessible = true
            module.hook(m).intercept { chain ->
                var r = chain.proceed() as? Boolean ?: return@intercept chain.proceed()
                if (!r || hidden.isEmpty()) return@intercept r
                val eventOut = chain.getArg(0) as? UsageEvents.Event
                    ?: return@intercept r

                var iterations = 0
                while (true) {
                    val pkg = runCatching { eventOut.packageName }.getOrNull()
                    if (pkg == null || !SweepList.isHidden(pkg, hidden)) {
                        return@intercept true
                    }
                    SweepList.logHit(module, "usage getNextEvent", pkg)
                    if (iterations++ > 100000) return@intercept false
                    r = runCatching { chain.proceed() }.getOrNull() as? Boolean
                        ?: return@intercept false
                    if (!r) return@intercept false
                }
                @Suppress("UNREACHABLE_CODE")
                false
            }
        }
    }

    // ------------------------------------------------------------------
    private fun hookGetNextEventOrNull(module: XposedModule) {
        hookSafe(module, "usage getNextEventOrNull") {
            val m = try {
                UsageEvents::class.java.getMethod("getNextEventOrNull")
            } catch (t: Throwable) {
                return@hookSafe
            }
            m.isAccessible = true
            module.hook(m).intercept { chain ->
                var r = chain.proceed() as? UsageEvents.Event
                    ?: return@intercept chain.proceed()
                if (hidden.isEmpty()) return@intercept r

                var iterations = 0
                while (true) {
                    val pkg = runCatching { r.packageName }.getOrNull()
                    if (pkg == null || !SweepList.isHidden(pkg, hidden)) {
                        return@intercept r
                    }
                    SweepList.logHit(module, "usage getNextEventOrNull", pkg)
                    if (iterations++ > 100000) return@intercept null
                    r = runCatching { chain.proceed() }.getOrNull() as? UsageEvents.Event
                        ?: return@intercept null
                }
                @Suppress("UNREACHABLE_CODE")
                null
            }
        }
    }

    // ------------------------------------------------------------------
    /**
     * Filter the UsageEvents in place.
     *
     * Strategy:
     *   1. Probe known field names: mEvents, mEventsToWrite, mEventList,
     *      events, mEventQueue. Pick whichever is a List and non-empty
     *      (or, failing that, whichever is a List at all).
     *   2. If none of the known names exist, scan every declared field for
     *      a List<Event>-shaped value. This is what catches OEM renames.
     *   3. Filter that list, set it back to the SAME field.
     *   4. Update mEventCount and reset mIndex if present.
     *   5. Never touch mStringPool - if the framework put null there it is
     *      because events carry direct String package names, and null is
     *      what the framework's own getNextEvent() expects.
     *
     * Diagnostics:
     *   - Logs the full declared-field list of UsageEvents once per process
     *     so a future framework change is visible in the log immediately
     *     instead of requiring another test cycle to diagnose.
     *
     * Return contract:
     *   null   -> caller returns the untouched result (passthrough)
     *   src    -> caller returns src, which is now filtered (or unchanged
     *             if removed == 0)
     */
    private fun filterEvents(
        module: XposedModule,
        src: UsageEvents,
        label: String
    ): UsageEvents? = runCatching {
        val cls = UsageEvents::class.java

        // One-shot field diagnostic - the fastest way to know what this
        // particular MuMu build actually declares.
        if (!fieldsLogged) {
            fieldsLogged = true
            val declared = runCatching {
                cls.declaredFields.joinToString(", ") { "${it.name}:${it.type.simpleName}" }
            }.getOrElse { "error: $it" }
            module.log(Log.INFO, TAG, "[PAS] $label: UsageEvents fields = [$declared]")
        }

        // 1. Find the events container.
        val preferred = listOf("mEvents", "mEventsToWrite", "mEventList", "events", "mEventQueue")
        var bestField: java.lang.reflect.Field? = null
        var bestList: List<UsageEvents.Event>? = null

        for (name in preferred) {
            val f = runCatching { cls.getDeclaredField(name).apply { isAccessible = true } }.getOrNull() ?: continue
            val value = runCatching { f.get(src) }.getOrNull() as? List<*> ?: continue
            @Suppress("UNCHECKED_CAST")
            val list = value as List<UsageEvents.Event>
            if (bestList == null || list.size > bestList.size) {
                bestField = f
                bestList = list
            }
        }

        // 2. Last resort: scan declared fields for a List<Event> shape.
        if (bestField == null) {
            for (f in cls.declaredFields) {
                if (!List::class.java.isAssignableFrom(f.type) && f.type != ArrayList::class.java) continue
                runCatching { f.isAccessible = true }
                val value = runCatching { f.get(src) }.getOrNull() as? List<*> ?: continue
                if (value.isNotEmpty() && value[0] is UsageEvents.Event) {
                    @Suppress("UNCHECKED_CAST")
                    bestField = f
                    @Suppress("UNCHECKED_CAST")
                    bestList = value as List<UsageEvents.Event>
                    break
                }
            }
        }

        if (bestField == null || bestList == null) {
            if (!eventsRebuildLogged) {
                eventsRebuildLogged = true
                module.log(Log.INFO, TAG, "[PAS] $label: no events container found — passthrough")
            }
            return@runCatching null
        }

        if (bestList.isEmpty()) return@runCatching src

        // 3. Filter.
        val kept = ArrayList<UsageEvents.Event>(bestList.size)
        var removed = 0
        for (e in bestList) {
            val pkg = runCatching { e.packageName }.getOrNull()
            if (pkg != null && SweepList.isHidden(pkg, hidden)) {
                removed++
                SweepList.logHit(module, label, pkg)
            } else {
                kept.add(e)
            }
        }
        if (removed == 0) return@runCatching src

        // 4. Write back to the SAME field we read from. Do NOT populate
        //    mEvents if we read from mEventsToWrite, or vice versa - that
        //    is exactly the inconsistency that caused v2.12.12/13 to leak.
        bestField.set(src, kept)

        // 5. Cursor / count consistency.
        runCatching {
            cls.getDeclaredField("mEventCount").apply { isAccessible = true }
                .setInt(src, kept.size)
        }
        runCatching {
            cls.getDeclaredField("mIndex").apply { isAccessible = true }
                .setInt(src, 0)
        }

        if (!eventsRebuildLogged) {
            eventsRebuildLogged = true
            module.log(Log.INFO, TAG,
                "[PAS] $label: filtered field '${bestField.name}' " +
                    "($removed hidden, ${kept.size} kept)")
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