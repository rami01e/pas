package com.kimera.pas.hooks

import android.util.Log
import io.github.libxposed.api.XposedModule
import com.kimera.pas.TAG
import com.kimera.pas.XHook
import com.kimera.pas.spoof.SpoofState

/**
 * ANTI-EMU (v3.0.0) - Java layer is a no-op guard.
 *
 * v3.0.0 (and v2.11.0 before it): the Build.* static-field patch via
 * sun.misc.Unsafe was REMOVED on purpose.
 *
 * Ownership rules that motivated this:
 *  - Build.BRAND / MODEL / DEVICE / PRODUCT / FINGERPRINT / ID / DISPLAY /
 *    TAGS / TYPE are initialized by ART from the ROM-level properties, so
 *    they already report whatever the KernelSU layer presents system-wide.
 *    Re-writing them per-app with the same values is dead weight.
 *  - Build.BOARD / HARDWARE / SOC_* are owned by the module's CPU toggle
 *    (SpoofCore patches them from the user's CPU profile). This hook used to
 *    hardcode exynos2100 over them - two writers racing on the same static
 *    final fields depending on thread timing.
 *  - Build.CPU_ABI / CPU_ABI2 / SUPPORTED_*_ABIS are owned by the module's
 *    CPU ABI toggle and were never touched here.
 *  - Build.HOST / USER mirrored ro.build.host / ro.build.user, which belong
 *    to the ROM identity layer (the KSU module can resetprop any build.prop
 *    value system-wide - per-app spoofing of these props has no use).
 *
 * The remaining anti-emu work is native-only (hide_antiemu.cpp v3.0.0):
 * path masking with ignorable-codepoint normalization, the qemu/emulator
 * property blanking, and the adb-runtime alignment pair - all runtime-gated
 * on SpoofState.antiEmuOn via SpoofCore.init -> nativeSetAntiEmu().
 *
 * This class is kept so XposedInit's hook array stays untouched. If you
 * prefer, delete this file and the HookAntiEmu() entry in
 * XposedInit.onPackageReady - behaviour is identical.
 */
class HookAntiEmu : XHook {

    override val targetKlass: String
        get() = "android.os.Build"

    override fun injectHook(module: XposedModule) {
        if (!SpoofState.antiEmuOn) {
            module.log(Log.INFO, TAG, "[PAS] ANTI-EMU off - Build.* not touched")
            return
        }
        module.log(Log.INFO, TAG, "[PAS] ANTI-EMU on - native-only scope, Build.* untouched")
    }
}