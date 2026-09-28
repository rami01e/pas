package me.hoshino.novpndetect

interface XHook {

    val targetKlass: String

    fun injectHook()
}