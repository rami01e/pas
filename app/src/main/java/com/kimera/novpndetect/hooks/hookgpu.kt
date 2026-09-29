package com.kimera.novpndetect.hooks

import android.opengl.GLES10
import android.opengl.GLES20
import android.util.Log
import io.github.libxposed.api.XposedModule
import com.kimera.novpndetect.TAG
import com.kimera.novpndetect.XHook
import com.kimera.novpndetect.hookSafe
import com.kimera.novpndetect.spoof.SpoofState

/**
 * GPU spoof (Java path): replaces the GL_VENDOR / GL_RENDERER strings that
 * Java-based OpenGL readers query; GL_EXTENSIONS / GL_VERSION are left
 * untouched so feature detection keeps working. The native layer covers the
 * same two strings for native GL callers (libGLESv2).
 */
class HookGpu : XHook {

    override val targetKlass: String
        get() = "android.opengl.GLES20"

    override fun injectHook(module: XposedModule) {
        hookGetString(module, GLES10::class.java)
        hookGetString(module, GLES20::class.java)
    }

    private fun hookGetString(module: XposedModule, clazz: Class<*>) {
        hookSafe(module, "GLES glGetString(${clazz.simpleName})") {
            val method = clazz.getMethod("glGetString", Int::class.javaPrimitiveType)
            module.hook(method).intercept { chain ->
                val name = chain.getArg(0) as? Int
                if (!SpoofState.gpuOn) {
                    chain.proceed()
                } else if (name == GL_VENDOR) {
                    module.log(Log.INFO, TAG, "[NVD] GL_VENDOR -> ${SpoofState.gpuVendor}")
                    SpoofState.gpuVendor
                } else if (name == GL_RENDERER) {
                    module.log(Log.INFO, TAG, "[NVD] GL_RENDERER -> ${SpoofState.gpuRenderer}")
                    SpoofState.gpuRenderer
                } else {
                    chain.proceed()
                }
            }
        }
    }

    private companion object {
        const val GL_VENDOR = 0x1F00
        const val GL_RENDERER = 0x1F01
    }
}
