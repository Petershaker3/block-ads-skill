# Block Ads — Always-On Rules / قواعد دائمة لمنع الإعلانات

You have Android ad-blocking and adware-removal capability available via the
`block-ads` skill. Apply these rules whenever the conversation touches ads,
overlays, adware, notification spam, or a device that hangs / loses touch.

Trigger phrases (Arabic or English): إعلانات، اعلانات،宣告، شيل الإعلانات،
منع الإعلانات، إزالة الإعلانات، ad, ads, adware, popup, overlay, notification
spam, التاتش مش شغال، الجهاز hangs، freeze، بطيء، تقفل الشاشة.

## Rules / القواعد

1. **Identify the channel before acting.** Overlay / fullscreen-intent /
   notification-listener / notification / DNS / malware are different problems
   with different fixes. Read `references/triage.md` from the `block-ads` skill.
2. **Find the owner first.** Use the `ads.scan` tool (or the equivalent adb
   commands) to identify the offending package. Never guess a package name.
3. **Never uninstall without explicit confirmation.** Show package name,
   install date and risk indicators first, then ask the user.
4. **Use the least destructive fix.** Escalation ladder in the skill:
   appop → appop → disallow_listener → `pm disable-user` → force-stop →
   uninstall. Only the last one is irreversible.
5. **Do not disable an accessibility service or device admin silently.** They
   are usually legitimate. Explain what it is and let the user decide.
6. **Do not enable root, developer options, or system settings** to fix ads.
7. **Always verify after changing anything** and show the command output.
8. **Windows host note:** `grep`/`head` do not exist in PowerShell. Put pipes
   inside `adb shell "..."` so they run on the device; use
   `Select-Object -First N` on the host. Never loop `appops get` over every
   package — use `cmd appops query-op SYSTEM_ALERT_WINDOW allow` instead.

## Quick channel map

| Symptom | Channel | First command |
| --- | --- | --- |
| Ad covers the screen / touch dead | overlay | `cmd appops query-op SYSTEM_ALERT_WINDOW allow` → check `duration=` in `appops get` |
| Activity opens over the lock screen | fullscreen intent | `dumpsys package <pkg> \| grep FULL_SCREEN` → `pm disable-user` |
| App watches/taps the screen | accessibility | `dumpsys accessibility` (installed + CallStack History) → `BIND_ACCESSIBILITY_SERVICE deny` |
| App reads or reposts my notifications | notification listener | `settings get secure enabled_notification_listeners` |
| Ads in the notification shade | notification | `appops set <pkg> POST_NOTIFICATION ignore` |
| Ads inside one app only | in-app | app's own settings |
| Ads in browser / every app | DNS | `settings get global private_dns_mode` (check first!) |
| New unknown package, obfuscated | malware | `python scripts/apk_scan.py <pkg> --pull` → uninstall after confirming |

**Truth-source notes:** `dumpsys device_policy` lists device admins, NOT
`dpm list-owners` (which only shows device/profile owners). Filter
`dumpsys window windows` on `APPLICATION_OVERLAY` — the raw dump lists every
window. A bare app-op `allow` is not proof; `time=`/`duration=` is.

Load the full `block-ads` skill for the complete procedure.
