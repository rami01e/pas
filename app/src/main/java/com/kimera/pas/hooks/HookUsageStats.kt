package com.kimera.pas.hooks

import android.app.usage.UsageEvents
import android.app.usage.UsageStatsManager
import android.util.Log
import io.github.libxposed.api.XposedModule
import com.kimera.pas.TAG
import com.kimera.pas.XHook
import com.kimera.pas.hookSafe

/**
 * vNEXT USAGE-STATS FILTER - closes the leak the com.playnearn capture
 * exposed (2026-10-20).
 *
 * The app posts a "Periodic report of usage stats" built from
 * UsageStatsManager. That surface bypasses PackageManager hooks entirely, so
 * HookSweep (which hides packages from getInstalledPackages / getPackageInfo)
 * never sees it. The report carried me.weishu.kernelsu,
 * org.frknkrc44.hma_oss, com.kimera.pas, com.termux, flar2.devcheck,
 * gr.nikolasspyr.integritycheck, krypton.tbsafetychecker,
 * com.android1500.gpssetter, com.mumu.store,
 * com.zaneschepke.wireguardautotunnel and com.android.vpndialogs - which is
 * exactly what produced the backend's "rooted device" and "VPN" marks.
 *
 * Covered surfaces:
 *   queryUsageStats(int, long, long)              -> List<UsageStats>
 *   queryAndAggregateUsageStats(long, long)       -> Map<String, UsageStats>
 *   queryEvents(long, long)                       -> UsageEvents (best effort,
 *                                                   rebuilt through the private
 *                                                   mEvents/mEventCount fields)
 *
 * Gated on the anti-emu toggle like the rest of the anti-emu layer: with the
 * toggle off this hook is never installed, so nothing changes.
 */
class HookUsageStats : XHook {

    override val targetKlass: String
        get() = "android.app.usage.UsageStatsManager"

    private var hidden: Set<String> = emptySet()
    private var eventsRebuildLogged = false

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
    /**
     * UsageEvents has no public builder; the container is rebuilt through its
     * private fields. If the runtime blocks that reflection the original
     * object is returned untouched (never crash the app over this).
     */
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
                filterEvents(module, events) ?: result
            }
        }
    }

    private fun filterEvents(module: XposedModule, src: UsageEvents): UsageEvents? = runCatching {
        val cls = UsageEvents::class.java
        val fEvents = cls.getDeclaredField("mEvents").apply { isAccessible = true }
        val raw = fEvents.get(src) as? ArrayList<*> ?: return@runCatching null
        val kept = ArrayList<Any?>(raw.size)
        var removed = 0
        for (e in raw) {
            val pkg = runCatching {
                (e as? UsageEvents.Event)?.packageName
            }.getOrNull()
            if (pkg != null && SweepList.isHidden(pkg, hidden)) {
                removed++
                SweepList.logHit(module, "usage queryEvents", pkg)
                continue
            }
            kept.add(e)
        }
        if (removed == 0) return@runCatching src
        val ctor = cls.getDeclaredConstructor().apply { isAccessible = true }
        val out = ctor.newInstance()
        fEvents.set(out, kept)
        runCatching {
            cls.getDeclaredField("mEventCount").apply { isAccessible = true }.setInt(out, kept.size)
        }
        if (!eventsRebuildLogged) {
            eventsRebuildLogged = true
            module.log(Log.INFO, TAG, "[PAS] usage-stats filter: queryEvents rebuilt ($removed hidden)")
        }
        out
    }.onFailure {
        if (!eventsRebuildLogged) {
            eventsRebuildLogged = true
            module.log(Log.INFO, TAG, "[PAS] usage-stats filter: queryEvents passthrough ($it)")
        }
    }.getOrNull()
}
