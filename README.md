# PURE ADBLOCK — Phase 1 Android Native Starter

- Native Android app written in Kotlin.
- Local `VpnService` and DNS-only filtering prototype.
- One-touch ON/OFF; Android displays its VPN consent dialog on first activation.
- Minimum Android: 8.0 (API 26); compile/target SDK: 35.

## Open and build
1. Install Android Studio and the Android SDK Platform 35.
2. Open this `PureAdBlock` folder in Android Studio.
3. Allow Gradle sync; use JDK 17.
4. Connect an Android phone with USB debugging enabled, or create an emulator.
5. Run the `app` configuration. To make an APK, choose **Build > Build Bundle(s) / APK(s) > Build APK(s)**.

## Important limitations of this phase
This is a DNS-filtering prototype, not a full packet-routing VPN. It handles IPv4 UDP DNS requests sent to its VPN DNS address. It does not yet handle TCP DNS, IPv6 DNS, DNS-over-HTTPS/TLS, or app-specific encrypted ad delivery. Ads served from the same domains as app content (common in some social/video/OTT apps) cannot reliably be separated by DNS blocklists. Therefore this build cannot promise 100% ad removal and may not block YouTube/Instagram/Facebook/streaming-service ads.

The app sends DNS queries that are not on the local blocklist to Cloudflare DNS (1.1.1.1). Add a privacy disclosure and test network behavior before public distribution. Only one Android VPN can be active at a time.

## Next engineering phases
1. Add a maintained, updateable domain blocklist and allowlist controls.
2. Add IPv6 and robust DNS parsing, retry/failure handling, and tests.
3. Add counters and per-domain diagnostics without collecting browsing history.
4. Evaluate encrypted DNS handling and app compatibility; do not claim support unless verified.
