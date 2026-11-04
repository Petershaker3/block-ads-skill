# Ad Source Triage — 命令清单 / قائمة أوامر الفحص

> Every command here is read-only. Run them BEFORE changing anything.
> Host is assumed to be Windows/PowerShell, but the `adb shell` side is the
> same everywhere. Where a pipe is needed, put it **inside** the `adb shell`
> quotes so it runs on the device (toybox has `grep`); `grep`/`head` do NOT
> exist on the Windows host itself.

## 0. Link check / فحص الاتصال

```powershell
adb devices -l
adb shell getprop ro.product.model
adb shell getprop ro.build.version.release
```

Device must show `device` (not `unauthorized`, `offline`, or `no devices`).

## 1. Overlay ads / إعلانات فوق التطبيقات

**Fastest way — one call lists every app with an explicit overlay grant:**

```powershell
adb shell "cmd appops query-op SYSTEM_ALERT_WINDOW allow"
```

This works on Android 10+ and returns just the packages. Do **not** loop
`appops get` over every package — on a device with 300 packages that is 300
round-trips and it will time out on WiFi.

Per-package check (for one suspect):

```powershell
adb shell appops get <package> SYSTEM_ALERT_WINDOW
```

| Output | Meaning |
| --- | --- |
| `allow` | it can draw over other apps |
| `ignore` | cannot draw, but you still get the permission dialog |
| `deny` | cannot draw |
| `default` | not explicitly set — it draws only after the user grants it |

Find who owns a floating window **right now** (filter on the overlay type —
the raw dump lists every activity, the status bar and the keyboard too):

```powershell
adb shell "dumpsys window windows | grep -B4 'APPLICATION_OVERLAY' | grep -E 'Window #|package='"
```

**Prove the app actually drew** — the access history beats a bare `allow`:

| Field | Meaning |
| --- | --- |
| `time=` | when it last drew the overlay |
| `duration=` | how long it held it (non-zero = it really covered the screen) |
| `rejectTime=` | when the system cut it off |

Bulk app-op dump (for a full audit):

```powershell
adb shell "dumpsys appops > /data/local/tmp/appops.txt"
adb pull /data/local/tmp/appops.txt .\appops.txt
```

Look for `SYSTEM_ALERT_WINDOW (allow):` under a `Package <name>:` header.
`default` entries are noise — only `allow` means the app can actually draw.

Android 12+ **system** overlays: `adb shell cmd overlay list` and
`adb shell cmd overlay disable <package>`. These only apply to packages under
`/system`; a third-party package throws
`SecurityException: Unable to retrieve overlay information`.

## 1b. Fullscreen-intent ads / إعلانات ملء الشاشة

An app with `USE_FULL_SCREEN_INTENT` can open an activity over the lock
screen or cover everything.

```powershell
adb shell "dumpsys package <pkg> | grep -i FULL_SCREEN"
```

The permission **cannot** be revoked:

```
adb shell pm revoke <pkg> android.permission.USE_FULL_SCREEN_INTENT
# SecurityException: ... is not a changeable permission type
```

There is no `MANAGE_APP_USE_FULL_SCREEN_INTENT` app-op before Android 14
(`Error: Unknown operation string`). The working lever is:

```powershell
adb shell pm disable-user --user 0 <pkg>     # reversible
adb shell pm enable <pkg>                    # revert
```

## 2. Accessibility services / خدمات إمكانية الوصول

An accessibility service can read every screen and click anything.

```powershell
adb shell settings get secure enabled_accessibility_services
adb shell settings get secure accessibility_enabled
```

`null` + `0` = clean. Anything else needs explaining to the user before removal.

A service can be **registered but not enabled** — it shows under
`installed services:` in `dumpsys accessibility` and can be re-enabled by its
own boot receiver without asking:

```powershell
adb shell "dumpsys accessibility | grep -A40 'installed services'"
adb shell "dumpsys accessibility | grep -A20 'CallStack History'"
```

The CallStack History records **who last wrote** the enabled-services
setting. A write by a non-Settings package (Shizuku, a hiding app) while the
visible list is empty = the service was enabled and then hidden — malware.

Block the binding so it cannot come back:

```powershell
adb shell cmd appops set <package> BIND_ACCESSIBILITY_SERVICE deny
adb shell cmd appops get <package> BIND_ACCESSIBILITY_SERVICE
```

## 2b. Notification listeners / مستمعو الإشعارات

A notification listener can read every notification on the device (and repost
them elsewhere).

```powershell
adb shell settings get secure enabled_notification_listeners
```

Remove one (exact `package/service` string from the list above):

```powershell
adb shell cmd notification disallow_listener <pkg>/<service> 0
```

## 3. Device admin / مدير الجهاز

Device admin can block uninstall and wipe data.

**`dumpsys device_policy` is the source of truth** — `dpm list-owners` only
lists device/profile *owners* and returns `no owners` even while regular
admins are active:

```powershell
adb shell "dumpsys device_policy | grep -A15 'Enabled Device Admins'"
adb shell dpm list-owners
```

If an offender is itself an admin, `dpm remove-active-admin <pkg>/<receiver>`
fails with `SecurityException: Attempt to remove non-test admin`. The
workaround is `pm disable-user --user 0 <pkg>` (works while admin) or
removing it by hand: Settings → Security → Device admin apps → off.

## 4. Ad notifications / إشعارات الإعلانات

```powershell
adb shell dumpsys notification
```

Look for `NotificationRecord(... pkg=<package> ...)` lines of packages you did
not expect. Ad channels are usually named like "Ads", "Promo", "Offers",
"General Ads" — read the channel name out of the same line:
`Notification(channel=ad_channel ...)`.

Block a package's notifications (verified op name — the permission is
`POST_NOTIFICATIONS` but the app-op is `POST_NOTIFICATION`):

```powershell
adb shell appops set <package> POST_NOTIFICATION ignore
adb shell appops get <package> POST_NOTIFICATION
```

Revert with `adb shell appops set <package> POST_NOTIFICATION allow`.

## 5. Which apps were just installed / التطبيقات المثبتة حديثاً

```powershell
adb shell pm list packages -3
adb shell dumpsys package <package> | findstr "firstInstallTime lastUpdateTime versionName"
```

A brand-new package with obfuscated class names is the prime suspect.

## 6. Fingerprint a suspect package / فحص حزمة مشبوهة

```powershell
python scripts/apk_scan.py <package> --pull
```

Reports risky permissions, manifest components and bundled ad SDKs.

## 7. Reading the manifest without aapt / قراءة المانيفست بدون أدوات

```powershell
adb shell pm path <package>
adb pull "<path>/base.apk" .\base.apk
```

`base.apk` is a zip: `AndroidManifest.xml` is binary AXML, `classes*.dex`
holds the code. The helper script parses both without extra tooling.

## 8. DNS state / حالة الـ DNS

```powershell
adb shell settings get global private_dns_mode
adb shell settings get global private_dns_specifier
```

`hostname` + a specifier means a filtering resolver is already configured.
Report it to the user; do not overwrite it without asking.

## 9. Runtime behaviour / السلوك وقت التشغيل

```powershell
adb logcat -c
adb logcat -d | findstr /i "<package>"
adb shell dumpsys activity activities | findstr "mFocusedApp"
adb shell dumpsys activity services | findstr "ServiceRecord"
```

A package that repeatedly tries `startForegroundService()` and gets
`not allowed due to mAllowStartForeground` is fighting the system for a
persistent overlay — that is the touch-blocking behaviour.

## 10. Wake locks / أقفال الاستيقاظ

An app holding a `PARTIAL_WAKE_LOCK` keeps the CPU awake, drains the
battery, and keeps running in the background.

```powershell
adb shell "dumpsys power | grep -i 'WAKE_LOCK'"
```

Map the uid back to a package:

```powershell
adb shell "dumpsys package packages | grep -B20 'userId=<uid>' | grep 'Package \['"
```

Stop the background work:

```powershell
adb shell am force-stop <pkg>
adb shell "cmd deviceidle whitelist -<pkg>"
```
