# block-ads-skill

> **English** below / [العربية بالأسفل](#العربية)

An [OpenCode](https://opencode.ai) skill that finds and removes the source of
annoying ads on Android — fullscreen overlays, ad notifications, notification
listeners, accessibility abuse, and adware/malware packages — over ADB, with
no root required.

**The ad is a symptom, the package is the cause.** The skill identifies the
offending package with evidence (install date, permissions, app-op access
history proving it actually drew an overlay), shows you the proof, and asks
before removing anything.

## What's inside

```
skills/block-ads/
├── SKILL.md              # the procedure (English + العربية)
├── references/triage.md   # every read-only triage command
└── scripts/
    ├── device_scan.py     # full device scan → report (~7s)
    └── apk_scan.py        # fingerprint one suspect package (ad SDKs, risky permissions)
plugins/block-ads/
├── index.mjs              # auto-activates on ad-related prompts + registers the ads.scan tool
└── always-on.md           # always-on ruleset injected into the session
commands/block-ads.md      # /block-ads slash command
```

## Install

```powershell
# skill
Copy-Item -Recurse skills\block-ads "$env:USERPROFILE\.config\opencode\skills\"

# plugin (always-on activation + ads.scan tool)
Copy-Item -Recurse plugins\block-ads "$env:USERPROFILE\.config\opencode\plugins\"

# command
Copy-Item commands\block-ads.md "$env:USERPROFILE\.config\opencode\commands\"
```

Linux/macOS: `~/.config/opencode/` instead of `%USERPROFILE%\.config\opencode\`.

**Requirements:** `adb` on PATH, an Android device in `adb devices` state,
Python 3.9+. No root.

## Use

- Automatic: mention ads / إعلانات / overlay / "التاتش مش شغال" and the skill
  attaches itself
- `/block-ads` — run the triage explicitly
- `@block-ads` — attach manually
- `ads.scan` tool — one call, full report

## Safety rules (built in)

- Nothing is uninstalled without an explicit yes for **that specific package**
- Escalation ladder: app-op → listener → `pm disable-user` → uninstall;
  only the last step is irreversible
- Accessibility services and device admins are explained, never silently disabled
- Existing Private DNS is read first, never overwritten blindly
- Every change is re-verified and the output is shown

---

<a id="العربية"></a>
# block-ads-skill — بالعربي

مهارة لـ OpenCode بتجد بتاع الإعلانات على أندرويد وتشيله عبر ADB من غير
root: إعلانات فوق التطبيقات، إشعارات إعلانات، تطبيقات بتسمع إشعاراتك،
إساءة استخدام accessibility، وحزم adware/malware.

**الإعلان عَرَض، والحزمة هي السبب.** المهارة بتورّك الدليل (تاريخ التثبيت،
الأذونات، سجل الـ app-op اللي بيثبت إن التطبيق رسم فعلاً) وبتسأل قبل ما
تشيل أي حاجة.

### التركيب

```powershell
Copy-Item -Recurse skills\block-ads "$env:USERPROFILE\.config\opencode\skills\"
Copy-Item -Recurse plugins\block-ads "$env:USERPROFILE\.config\opencode\plugins\"
Copy-Item commands\block-ads.md "$env:USERPROFILE\.config\opencode\commands\"
```

**المتطلبات:** `adb` في PATH، جهاز أندرويد ظاهر في `adb devices`، Python 3.9+.
من غير root.

### الاستخدام

- **تلقائي**: أي رسالة فيها إعلانات / شيل الإعلانات / التاتش مش شغال
- `/block-ads` — تشغيل الفحص صراحةً
- `@block-ads` — إرفاق يدوي
- أداة `ads.scan` — تقرير كامل بنداء واحد

### قواعد الأمان المدمجة

- مفيش مسح من غير موافقتك الصريحة على **الحزمة المحددة**
- سلّم تصعيد: app-op ← listener ← `pm disable-user` ← مسح (الأخير فقط غير
  قابل للتراجع)
- خدمات accessibility و device admins بتتشرح لك مش بتتعطّل في الخفي
- الـ Private DNS الحالي بيتقرا الأول مش بيتعمله overwrite
- كل تعديل بيتعاد فحصه وتُعرض نتيجته
