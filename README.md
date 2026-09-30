# PerAppSpoofer

**Per-app device identity & environment spoofing for Android — by KiMeRa**

PerAppSpoofer is an LSPosed / Vector module (libxposed API 101) that presents a controlled, consistent device identity to *only the apps you choose*. Everything else on the system keeps seeing the real device. It is built for testing, research and privacy work on your own devices and emulators.

## What it can do

- **Per-app scope** — spoofing applies only to the apps you select; nothing system-wide.
- **Device identity presentation** — SDK level, CPU ABI, CPU and GPU model (build fields, system properties, `/proc` views, frequency mirrors, OpenGL/Vulkan identity), kept consistent across surfaces.
- **DRM / account identifiers** — Widevine report level + device id, GSF id.
- **Connectivity presentation** — hides VPN/tunnel traces from connectivity APIs so apps that distrust VPN leftovers can be tested normally.
- **Modern browser & WebView coverage** — GPU identity surfaces used by Chromium-based browsers are covered, including dynamic resolver paths.
- **Built-in diagnostics** — an opt-in recon mode records which probes a target app performs, plus an in-app module log viewer.
- **Safety first** — every feature is opt-in; disabled features install nothing at all. A compatibility mode skips extended hook groups for the most demanding apps. Native hooks never touch ARM-translated libraries.

## Requirements

- Android 8.0+ (API 26+), arm64-v8a / x86_64 / x86
- Vector (LSPosed fork) with libxposed API 101 (2.2+)
- Root is optional — needed only for the in-app log viewer.

## Install

1. Download the latest `app-release.apk` from **Releases**.
2. Install the APK, then enable the module in Vector and pick your scope.
3. Open the module app, choose your spoof set, hit **Apply**, then restart the scoped apps (spoofs take effect at process start).

## Build

Every push produces a debug APK; every tag produces a release APK — all through GitHub Actions. For local builds: Android SDK 34 + NDK 27, then `./gradlew :app:assembleDebug`.

## Notes

- Restart scoped apps after changing settings — hooks are installed when a process starts.
- Use only on devices and apps you own or are authorized to test.

---

by **KiMeRa**