package com.kimera.pas.hooks

import android.util.Log
import io.github.libxposed.api.XposedModule
import com.kimera.pas.TAG
import com.kimera.pas.XHook
import com.kimera.pas.spoof.SpoofState

/**
 * ANTI-EMU (v3.1.0) - Java layer: exec-shield wiring.
 *
 * Ownership history:
 *  - v2.11.0/v3.0.0: the Build.* static-field patch via sun.misc.Unsafe was
 *    REMOVED on purpose (Build.BRAND/MODEL/... are ROM-prop driven and the
 *    KSU module already owns them system-wide; BOARD/HARDWARE/SOC_* belong
 *    to the CPU toggle; HOST/USER belong to the ROM identity layer).
 *  - v3.1.0: the Java exec shield (HookExec) is wired from here because it
 *    IS part of anti-emu: it closes the child-process bypass of the native
 *    masks and carries the two Duck-aligned exec channels:
 *      - `getprop` dumps re-served with the adb-runtime alignment the
 *        native prop layer serves in-process (Duck item 8: reflection
 *        "mtp" vs exec'd dump "adb" divergence), and
 *      - `uname -a` output stripped of maintainer-style @mentions, agreeing
 *        with the sanitized /proc/version + utsname views (Duck item 2).
 *    HookExec self-gates every interceptor on SpoofState.antiEmuOn, so it
 *    is registered unconditionally and toggling anti-emu applies live
 *    without a process restart.
 *
 * The remaining anti-emu work is native-only (hide_antiemu.cpp v3.1.0):
 * path masking with ignorable-codepoint normalization, the qemu/emulator
 * property blanking, the adb-runtime alignment pair, the kernel-identity
 * @mention strip (uname + /proc/version + kernel sysctls), the residue-view
 * filtering (maps/mounts/net-unix/environ), the fd-link + getenv scrubbing,
 * and the bytehook once-only CALL_PREV fix that kept the CPU spoof from
 * rendering while anti-emu was armed - all runtime-gated on
 * SpoofState.antiEmuOn via SpoofCore.init -> nativeSetAntiEmu().
 */
class HookAntiEmu : XHook {

    override val targetKlass: String
        get() = "android.os.Build"

    override fun injectHook(module: XposedModule) {
        // v3.1.0: exec shield is anti-emu-owned; registered unconditionally
        // because every interceptor re-checks SpoofState.antiEmuOn per call.
        runCatching {
            HookExec().injectHook(module)
        }.onFailure {
            module.log(Log.INFO, TAG, "[PAS] ANTI-EMU exec shield wiring failed: $it")
        }
        if (!SpoofState.antiEmuOn) {
            module.log(Log.INFO, TAG, "[PAS] ANTI-EMU off - Build.* not touched")
            return
        }
        module.log(Log.INFO, TAG, "[PAS] ANTI-EMU on - exec shield wired, Build.* untouched")
    }
}