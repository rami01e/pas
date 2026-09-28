package me.hoshino.novpndetect.util

fun getRandomString(length: Int) : String {
    val allowedChars = ('a'..'z') + ('0'..'9')
    return (1..length)
        .map { allowedChars.random() }
        .joinToString("")
}