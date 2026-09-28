package me.hoshino.novpndetect

import android.util.Log
import io.github.libxposed.api.XposedModule

interface XHook {

    val targetKlass: String

    fun injectHook(module: XposedModule)
}

/**
 * Installs a hook, catching and logging failures so a single missing method
 * cannot prevent the remaining hooks from being installed.
 */
fun hookSafe(module: XposedModule, label: String, block: () -> Unit) {
    try {
        block()
    } catch (t: Throwable) {
        module.log(Log.INFO, TAG, "hook failed: $label: $t")
    }
}
