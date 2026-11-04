---
name: block-ads
description: Use when ads pop up over apps, fullscreen ad overlays block the screen, ad notifications flood the shade, the device hangs or the touch stops responding, or the user asks to remove/block ads or remove an adware app ("شيل الإعلانات", "منع الإعلانات", "إعلانات فوق التطبيقات", "الجهاز hangs", "التاتش مش شغال"). Covers ADB-driven triage and removal of ad SDKs, overlay adware, and ad notifications on any Android device.
compatibility: Requires the `adb` binary on PATH and an Android device in `adb devices` state. Python 3.9+ for the bundled scanner scripts. No root required.
allowed-tools: Bash(adb:*) Bash(python:*) Bash(python3:*) Read Write Edit
metadata:
  opencode/display-name: "Block Ads / منع الإعلانات"
  opencode/language: "ar + en"
  opencode/version: "1.0"
---

# Block Ads / منع الإعلانات

## Overview

Ads on Android arrive through a small number of **channels**, and each channel
has a different removal. Identify the channel first, then apply the matching
fix. Never guess.

| Channel | Symptom | Fix |
| --- | --- | --- |
| **Overlay / floating ad** | Ad drawn on top of every app, blocks touch, screen goes black | Revoke `SYSTEM_ALERT_WINDOW` appop; force-stop; uninstall the owner |
| **Fullscreen intent** | An activity opens over the lock screen / covers everything | `pm disable-user` the package (the permission itself cannot be revoked) |
| **Notification listener** | Another app reads/reposts every notification | `cmd notification disallow_listener` |
| **In-app ad** | Banner/interstitial inside the app the user is using | Disable the ad SDK inside the app's own settings, or disable the package's notifications |
| **Notification ad** | Ad pushes in the shade | `appops set <pkg> POST_NOTIFICATION ignore` |
| **DNS / network ad** | Ads load from the network in any app or browser | Private DNS (AdGuard / NextDNS) — check what is already set first |
| **Malware / adware app** | Unknown package, obfuscated names, boot receiver, foreground service | Uninstall it (this is a malware case, not an ads case) |

**Core principle: the ad is a symptom, the package is the cause.** Never
"block ads" globally with a blunt tool when a single package is the source.

## When to Use

- Ads cover the screen or the app under the user cannot be tapped.
- The device freezes, hangs, or the touch stops responding.
- The shade is flooded with ad pushes from an unknown app.
- The user asks in Arabic or English to remove/block ads, remove an adware
  app, or fix a device that keeps showing ads.
- A newly installed app turns out to be an adware/malware package.

**Not** for: web ad blocking in a desktop browser, YouTube Premium, or
business ad-campaign analytics.

## Workflow

### 1. Confirm the device link / تأكيد الاتصال

```powershell
adb devices -l
adb shell getprop ro.product.model
```

If the device is missing, `unauthorized`, or `offline`: stop and tell the
user to reconnect/re-accept the USB debugging prompt. Do not continue with
guessed device state.

### 2. Classify the symptom / تحديد نوع المشكلة

Ask ONE clarifying question if the symptom is ambiguous, using this mapping:

- "Ad appears on top of the app / covers the whole screen" → **Overlay**
- "Ad shows inside one specific app" → **In-app**
- "Ads arrive as pushes in the notification shade" → **Notification**
- "Ads load in the browser / every app" → **DNS**
- "The phone hangs, touch stops working" → **Overlay or malware** → go to step 3 immediately

### 3. Triage — find the owner / تحديد المسبّب

**Preferred:** run the bundled scanner, which batches every probe into a
handful of adb calls (≈7s on a WiFi device):

```powershell
python scripts/device_scan.py          # text report
python scripts/device_scan.py --json   # machine-readable
```

In OpenCode, the plugin exposes this as the **`ads_scan`** tool — call it
instead of hand-assembling commands.

Manual equivalent (see `references/triage.md` for the full list):

```powershell
# who is ALLOWED to draw overlays — one call, no per-package loop
adb shell "cmd appops query-op SYSTEM_ALERT_WINDOW allow"

# accessibility abuse (can read every screen)
adb shell settings get secure enabled_accessibility_services
adb shell settings get secure accessibility_enabled

# notification listeners (can read/repost every notification)
adb shell settings get secure enabled_notification_listeners

# device admin (can block uninstall) — dumpsys is the truth source;
# `dpm list-owners` only lists device/profile OWNERS and returns "no owners"
# even while regular admins are active
adb shell "dumpsys device_policy | grep -A12 'Enabled Device Admins'"

# notification ads
adb shell dumpsys notification

# who holds a wake lock (battery drain + background activity)
adb shell "dumpsys power | grep -i 'WAKE_LOCK'"

# recently installed third-party packages
adb shell pm list packages -3
```

> **Windows note:** `grep` and `head` do not exist on the PowerShell host.
> Put the pipe **inside** the `adb shell "..."` quotes so toybox handles it on
> the device. Use `Select-Object -First N` on the host side instead of `head`.
> A per-package loop (`appops get` for each of 300 packages) takes minutes and
> stalls on WiFi — always use one bulk dump.
>
> **Op-name note:** the permission is `POST_NOTIFICATIONS` but the app-op is
> `POST_NOTIFICATION` (singular). Same for `SYSTEM_ALERT_WINDOW`, which is
> identical in both.

### 4. Fingerprint the suspect / فحص الحزمة المشبوهة

```powershell
python scripts/apk_scan.py <package> --pull
```

Shows risky permissions, obfuscated manifest components and bundled ad SDKs
(AppLovin, Vungle, Bigo, Mintegral, AdMob, Unity Ads, InMobi, …).

**Malware indicators** (treat as malware, not as "ads"):

- installed today / very recently
- obfuscated class names (`com.whlwjnt.ldrltp.Kjljuwuh`)
- `MANAGE_OWN_CALLS` or `BIND_TELECOM_CONNECTION_SERVICE`
- `RECEIVE_BOOT_COMPLETED` + `FOREGROUND_SERVICE` + `WAKE_LOCK`
- 4+ ad SDKs bundled at once
- tries `startForegroundService()` and is refused by the system

**Prove it actually drew the overlay** — the app-op access history is the
strongest evidence, better than a bare `allow`:

```powershell
adb shell appops get <package> SYSTEM_ALERT_WINDOW
```

```
SYSTEM_ALERT_WINDOW: allow; time=+11h31m59s ago; duration=+48s583ms
```

`time` = when it last drew, `duration` = how long it held the overlay,
`rejectTime` = when the system cut it off. A non-zero `duration` means the
app really covered the screen — that is the line to show the user.

### 5. Apply the fix / تطبيق الحل

Pick by channel. Order matters: **stop → revoke → uninstall**.

**Overlay ads**
```powershell
adb shell am force-stop <package>
adb shell cmd appops set --user 0 <package> SYSTEM_ALERT_WINDOW deny
```

Revert with `adb shell cmd appops set --user 0 <package> SYSTEM_ALERT_WINDOW default`.

`cmd overlay disable <package>` only works for **system** overlays (packages
under `/system`). For a third-party app it throws
`SecurityException: Unable to retrieve overlay information` — use the appop
route above instead. Check `adb shell cmd overlay list` to see which system
overlays exist.

**Fullscreen-intent ads** (an activity that covers the screen / the lock screen)

`USE_FULL_SCREEN_INTENT` **cannot** be revoked — `pm revoke` fails with
`SecurityException: ... is not a changeable permission type`, and there is no
`MANAGE_APP_USE_FULL_SCREEN_INTENT` app-op on Android 12. The working lever
is disabling the package:

```powershell
adb shell pm disable-user --user 0 <package>
```

Revert with `adb shell pm enable <package>`. This keeps the APK and the data
— it is reversible, unlike uninstall. It is also the safest middle step
between "revoke one permission" and "delete the app".

**Notification listeners** (an app reading or reposting every notification)

Show the user the list first — a launcher needs its own listener, so a
blanket disable breaks notification dots on the home screen. Remove one
exact `package/service` string at a time:

```powershell
adb shell cmd notification disallow_listener <package>/<service_class> 0
```

Read the exact `package/service` strings from
`adb shell settings get secure enabled_notification_listeners`.

**Accessibility abuse** (an app watching the screen and tapping it)

An enabled service shows in `settings get secure enabled_accessibility_services`.
A service that is only *registered* (shows under `installed services` in
`dumpsys accessibility`) is not active but can be re-enabled by its own boot
receiver. Block the binding itself so it cannot come back:

```powershell
adb shell cmd appops set <package> BIND_ACCESSIBILITY_SERVICE deny
```

If the service is currently enabled, disable it in Settings first (or
`settings put secure enabled_accessibility_services ''` after showing the
user the list), then apply the app-op deny.

**Watch for tampering:** `dumpsys accessibility` keeps a history of who
last wrote the enabled-services setting. Writes by a non-Settings package
(Shizuku, a "hiding" app) while the visible list is empty is a strong
malware signal — the service was enabled and then hidden.

**Device admin** (the offender is itself an admin — it blocks uninstall)

`dpm remove-active-admin <pkg>/<receiver>` fails with
`SecurityException: Attempt to remove non-test admin` for real admins. In
that order:

```powershell
adb shell pm disable-user --user 0 <package>    # works even while admin
```

If `disable-user` must not be used, the user removes it by hand:
Settings → Security → Device admin apps → toggle it off, then uninstall.

> `pm disable-user` can also fail with `SecurityException` on packages the
> OEM protects or that are already disabled — check
> `adb shell dumpsys package <pkg> | grep -A2 "flags"` before assuming the
> command works.

**Notification ads**

Block the package's notifications at the app-op level (verified working on
Android 12+; `POST_NOTIFICATION` is the op name, not `POST_NOTIFICATIONS`):

```powershell
adb shell appops set <package> POST_NOTIFICATION ignore
```

Verify, and read the channel names the package owns:

```powershell
adb shell appops get <package> POST_NOTIFICATION
adb shell dumpsys notification | grep -i "<package>"
```

To disable a single ad channel instead of all of the package's notifications:

```powershell
adb shell cmd notification set_bubbles_channel <package> <channel_id> 0
```

Or revoke the runtime permission entirely:

```powershell
adb shell pm revoke <package> android.permission.POST_NOTIFICATIONS
```

> `cmd notification set_dismissible` does **not** exist — check
> `adb shell cmd notification help` before using any `cmd notification`
> subcommand.

**DNS / network ads** (device-wide, no root)

**Check what is already set first — do not overwrite it blindly:**

```powershell
adb shell settings get global private_dns_mode
adb shell settings get global private_dns_specifier
```

If `private_dns_mode` is already `hostname` with a specifier, the device
already has a filtering resolver (NextDNS, AdGuard, Mullvad, …). **Tell the
user what is configured and let them decide** before replacing it — silently
swapping their DNS breaks whatever else it is doing (DoH, parental controls,
per-device rules).

To switch to a blocking resolver:

```powershell
adb shell settings put global private_dns_mode hostname
adb shell settings put global private_dns_specifier dns.adguard-dns.com
```

Verify with `adb shell settings get global private_dns_specifier`. To revert
to automatic: `adb shell settings put global private_dns_mode off`.

> DNS blocking does **not** stop on-device overlay ads. It only handles ads
> loaded from the network.

**Malware / adware app**

> **STOP.** Before the uninstall below, show the user the package name, the
> install date and the risk indicators, and get an explicit "yes" to remove
> **that specific package**. If they say no, drop to the escalation ladder
> (`pm disable-user`) and offer that instead.

Then run these one at a time (never chained, so a failure is visible):

```powershell
adb shell am force-stop <package>
```

```powershell
adb uninstall <package>
```

### 6. Verify / التحقق

```powershell
adb shell "cmd appops query-op SYSTEM_ALERT_WINDOW allow"
adb shell pm list packages | findstr <package>   # must be empty after uninstall
adb shell dumpsys activity activities | findstr "mFocusedApp"
```

After removing the offending package the device must return to a responsive
launcher. If the touch is still dead, the overlay owner is a different
package — go back to step 3.

Also re-check the wake locks — an ad app that is still running in the
background will keep a `PARTIAL_WAKE_LOCK` and keep the device hot:

```powershell
adb shell "dumpsys power | grep -i 'WAKE_LOCK'"
```

## Escalation Ladder / سلّم التصعيد

Use the least destructive step that solves it, and stop as soon as the ads
stop. Each step is reversible except the last.

| Step | Action | Reversible? | Use when |
| --- | --- | --- | --- |
| 1 | `appops set <pkg> POST_NOTIFICATION ignore` | yes | ad pushes in the shade |
| 2 | `appops set <pkg> SYSTEM_ALERT_WINDOW deny` | yes | floating / fullscreen overlay |
| 3 | `cmd notification disallow_listener <pkg>/<svc> 0` | yes | app reads or reposts notifications |
| 3b | `appops set <pkg> BIND_ACCESSIBILITY_SERVICE deny` | yes | app watches/taps the screen |
| 4 | `pm disable-user --user 0 <pkg>` | yes (`pm enable`) | fullscreen intent, device admin offender, keeps waking the device |
| 5 | `am force-stop <pkg>` | yes | kill the current session only |
| 6 | `adb uninstall <pkg>` | **no** | confirmed malware / adware |

Do not jump to step 6 while the user still wants the app.

## Hard Rules

**Human-in-the-loop is mandatory. Nothing gets removed without an explicit
"yes" from the user in the conversation.**

- **Never uninstall without explicit confirmation.** Show the package name,
  install date and the risk indicators first, then ask. Removing an app can
  destroy user data.
- **Never run a destructive command as part of a batch.** One command at a
  time, each one verified before the next. A chained
  `force-stop && appops set && uninstall` hides which step failed.
- **Do not disable the accessibility service or device admin** without telling
  the user what it is. These are usually legitimate (banking apps, corporate
  MDM, screen readers). Say what it is and let the user decide.
- **Do not enable Developer options, root, or system settings** to "fix" ads.
  Ads are not a root problem.
- **Never delete apps, APKs, or data outside the device** without asking.
- **Never use `pm uninstall -k --user 0` as a "safe" middle ground.** It looks
  reversible but leaves the APK and data behind. Use `pm disable-user` for a
  reversible step.
- **Never disable every notification listener at once** — the launcher needs
  its own. Disallow them one at a time.
- **Always show the evidence.** Package name + install date + permission list
  beats "some app is causing ads".
- **Re-verify after every change.** A fix that is not verified is not a fix.

### Red Flags — STOP and ask

- You are about to run `adb uninstall` and the user has not said yes to *that*
  specific package.
- You are about to remove an app the user named as one they use ("I need
  WhatsApp") — that is a workaround, not a fix. Find the real offender.
- You are about to revoke `SYSTEM_ALERT_WINDOW` from a launcher, the system
  UI, or the dialer — that breaks the device.
- You are tempted to batch several `adb` commands behind `;` or `&&` so you
  only report once.
- You are about to report "done" without re-running the scan or the check.

## Report Format / شكل التقرير

Report in the user's language (Arabic → Egyptian dialect, RTL wrapping for
Arabic paragraphs). Structure:

```
## Diagnosis / التشخيص
- Symptom channel: overlay / notification / in-app / DNS / malware
- Offending package: `<pkg>` (installed <date>)

## Evidence / الدليل
- <permission or logcat or dumpsys line>

## Actions taken / الإجراءات
1. <command> → <result>

## Prevention / الوقاية
- <one or two concrete next steps>
```

Keep it short: the user wants the phone fixed, not a lecture.

## Common Mistakes

| Mistake | Why it fails | Do instead |
| --- | --- | --- |
| `adb shell cmd overlay list` on Android 11 | command does not exist | use `dumpsys window windows` + `appops` |
| `grep`/`head` on the Windows host | not installed | pipe inside `adb shell "..."` |
| `adb uninstall` without asking | destroys user data | confirm first |
| Revoking `SYSTEM_ALERT_WINDOW` on a launcher | breaks the launcher | only revoke on the confirmed offender |
| `pm revoke <pkg> android.permission.USE_FULL_SCREEN_INTENT` | not a changeable permission type | `pm disable-user --user 0 <pkg>` |
| `cmd appops get <pkg> MANAGE_APP_USE_FULL_SCREEN_INTENT` | unknown operation string on Android 12 | there is no such app-op; use `pm disable-user` |
| `cmd overlay disable <third-party-pkg>` | `SecurityException`, system overlays only | revoke the app-op instead |
| `appops set <pkg> POST_NOTIFICATIONS ignore` | wrong op name | it is `POST_NOTIFICATION` (singular) |
| `cmd notification set_dismissible` | subcommand does not exist | check `cmd notification help` first |
| Trusting `dpm list-owners` to list admins | returns `no owners` while admins are active | `dumpsys device_policy` → "Enabled Device Admins" |
| `dpm remove-active-admin <real-admin>` | `SecurityException: non-test admin` | `pm disable-user`, or manual toggle in Settings |
| Treating every `dumpsys window windows` package as an overlay | lists activities, status bar, keyboard too | filter on `APPLICATION_OVERLAY` type only |
| Treating a bare `allow` as proof | grant ≠ it drew anything | check `time=`/`duration=` in `appops get` |
| Overwriting `private_dns_specifier` blindly | breaks the user's existing DNS filter | read the current value, then ask |
| Setting DNS to a blocking resolver and calling the case closed | does not stop on-device overlays | DNS handles network ads only |
| Reporting "fixed" without re-running the check | unverified claim | always re-check and show the output |
