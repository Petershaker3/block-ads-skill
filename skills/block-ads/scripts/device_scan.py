#!/usr/bin/env python3
"""
Device-wide ad / adware triage for Android over ADB (no root required).

Usage:
    python device_scan.py            # full scan
    python device_scan.py --json     # machine-readable output
    python device_scan.py --shallow  # skip the slower dumpsys probes

Design notes:
  * Every probe is ONE batched adb call. A per-package loop over `appops get`
    needs hundreds of round-trips and stalls on flaky WiFi links, so the
    scanner reads the whole dumpsys output instead and parses it locally.
  * Pipes belong INSIDE the `adb shell "..."` quotes so toybox runs them on the
    device. `grep`/`head` do not exist on a Windows host.

Exit codes: 0 = ok, 2 = no device / adb missing.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys

TIMEOUT = 60

# Package names are interpolated into `adb shell` strings. Restrict them to
# the characters Android actually allows so a crafted name can never become
# a second shell command on the device.
PKG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._]{0,254}$")


def valid_pkg(name: str) -> bool:
    return bool(PKG_RE.match(name))


def adb(args: list[str], timeout: int = TIMEOUT) -> str:
    try:
        p = subprocess.run(
            ["adb", *args],
            capture_output=True,
            text=True,
            timeout=timeout,
            errors="replace",
            shell=False,
        )
    except FileNotFoundError:
        print("adb not found on PATH", file=sys.stderr)
        sys.exit(2)
    except subprocess.TimeoutExpired:
        return ""
    return p.stdout


def shell(cmd: str, timeout: int = TIMEOUT) -> str:
    return adb(["shell", cmd], timeout=timeout)


def device_ok() -> bool:
    out = adb(["devices"])
    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 2 and parts[1] == "device":
            return True
    return False


# --------------------------------------------------------------------------
# probes
# --------------------------------------------------------------------------

def device_identity() -> dict:
    props = {
        "model": "ro.product.model",
        "brand": "ro.product.brand",
        "android": "ro.build.version.release",
        "sdk": "ro.build.version.sdk",
        "build": "ro.build.display.id",
    }
    out = {}
    for key, prop in props.items():
        out[key] = shell(f"getprop {prop}").strip()
    return out


def overlay_window_owners() -> list[str]:
    """Packages that currently own an APPLICATION_OVERLAY window.

    `dumpsys window windows` lists every window (activities, status bar,
    keyboard ...). Only blocks whose type is APPLICATION_OVERLAY are real
    overlays drawn on top of other apps — everything else is noise.
    """
    out = shell("dumpsys window windows", timeout=90)
    owners: list[str] = []
    for block in re.split(r"(?=^\s*Window #)", out, flags=re.MULTILINE):
        if "APPLICATION_OVERLAY" not in block:
            continue
        # Header shape: Window{hash u0 com.pkg/.Activity}
        m = re.search(r"Window\{\S+ \S+ ([A-Za-z0-9_.]+)/", block)
        if m:
            pkg = m.group(1)
        else:  # fallback: some builds print package= inside the block
            fm = re.search(r"\bpackage=(\S+)", block)
            if not fm:
                continue
            pkg = fm.group(1)
        if pkg in ("android", "com.android.systemui", "com.android.launcher3", "com.android.launcher"):
            continue
        if pkg not in owners:
            owners.append(pkg)
    return owners


def overlay_appops() -> dict[str, dict]:
    """package -> {mode, last_draw, duration} for SYSTEM_ALERT_WINDOW.

    The dump looks like:

        Package com.example.ads:
          SYSTEM_ALERT_WINDOW (allow):
            null=[
              Access: [pers-s] 2026-11-03 15:31:23.254 (-9h22m36s258ms) duration=+2s244ms
            ]

    mode == "allow" means it MAY draw; last_draw/duration prove it ACTUALLY
    drew — that access history is the strongest available evidence.
    """
    out = shell("dumpsys appops", timeout=180)
    result: dict[str, dict] = {}
    pkg: str | None = None
    lines = out.splitlines()
    for i, line in enumerate(lines):
        m = re.match(r"\s*Package\s+([A-Za-z0-9_.]+):\s*$", line)
        if m:
            pkg = m.group(1)
            continue
        if "SYSTEM_ALERT_WINDOW" not in line or pkg is None:
            continue
        mm = re.search(r"SYSTEM_ALERT_WINDOW\s*\(([a-z]+)\)", line)
        if not mm:
            continue
        mode = mm.group(1)
        entry = result.setdefault(pkg, {"mode": mode, "last_draw": "", "duration": ""})
        if mode == "allow":
            entry["mode"] = "allow"  # explicit grant wins over default
        # Look ahead a few lines for the access record.
        for j in range(i + 1, min(i + 5, len(lines))):
            am = re.search(
                r"Access:.*?(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?)"
                r".*?duration=(\S+)",
                lines[j],
            )
            if am:
                if not entry["last_draw"] or am.group(1) > entry["last_draw"]:
                    entry["last_draw"] = am.group(1)
                    entry["duration"] = am.group(2)
                break
            if re.search(r"Reject:", lines[j]):
                break
    return result


def accessibility_services() -> list[str]:
    out = shell("settings get secure enabled_accessibility_services").strip()
    if not out or out.lower() == "null":
        return []
    return [s for s in out.split(":") if s]


def notification_listeners() -> list[str]:
    """Apps that can read every notification on the device."""
    out = shell("settings get secure enabled_notification_listeners").strip()
    if not out or out.lower() == "null":
        return []
    return [s for s in out.split(":") if s]


def fullscreen_intent_packages() -> list[str]:
    """Packages granted USE_FULL_SCREEN_INTENT — these can cover the screen."""
    out = shell("dumpsys package packages", timeout=180)
    hits: list[str] = []
    for block in re.split(r"\n\s*Package \[", out)[1:]:
        m = re.match(r"([A-Za-z0-9_.]+)\]", block)
        if not m:
            continue
        if "android.permission.USE_FULL_SCREEN_INTENT: granted=true" in block:
            hits.append(m.group(1))
    return hits


def wake_lock_holders() -> list[dict]:
    """Packages holding a wake lock (battery drain + background activity)."""
    out = shell("dumpsys power", timeout=120)
    holds: list[dict] = []
    for line in out.splitlines():
        if "WAKE_LOCK" not in line:
            continue
        m = re.search(r"'(.*?)'.*\(uid=(\d+)", line)
        if not m:
            continue
        holds.append({"lock": m.group(1), "uid": m.group(2), "raw": line.strip()})
    return holds


def accessibility_history() -> list[dict]:
    """Every recorded change to `enabled_accessibility_services`.

    `dumpsys accessibility` keeps a ring buffer of the last ~20 writes to the
    setting, with the package that wrote it. A write by a package that is not
    the Settings UI (Shizuku, a "hiding" app, ...) is a tampering signal even
    when the resulting value is empty (value empty = services were cleared).
    """
    out = shell("dumpsys accessibility", timeout=150)
    entries: list[dict] = []
    for m in re.finditer(
        r"history\s*\[\d+\]\s*:\s*\n\s*([\d\-: ]+)\s*\n\s*value\s*:\s*(.*?)\s*\n\s*package\s*:\s*(\S+)",
        out,
    ):
        when, value, pkg = m.group(1).strip(), m.group(2).strip(), m.group(3).strip()
        entries.append({"when": when, "service": value, "changed_by": pkg})
    return entries


def installed_accessibility_services() -> list[str]:
    """Services registered with the accessibility manager (enabled or not).

    An enabled list can be empty while a malicious service still sits
    registered and ready to be re-enabled by its boot receiver — the
    `installed services` block is where it shows up.
    """
    out = shell("dumpsys accessibility", timeout=150)
    m = re.search(r"installed services:\s*\{(.*?)\n\s*\}", out, re.DOTALL)
    if not m:
        return []
    return [
        s.strip()
        for s in re.findall(r"\d+\s*:\s*(\S+)", m.group(1))
        if s.strip()
    ]


def accessibility_binders() -> list[str]:
    """Packages allowed to BIND_ACCESSIBILITY_SERVICE (can watch the screen)."""
    out = shell("cmd appops query-op BIND_ACCESSIBILITY_SERVICE allow", timeout=90)
    return [l.strip() for l in out.splitlines() if l.strip() and " " not in l.strip()]


def device_admin_details() -> list[dict]:
    """Active device admins, with the policies they hold."""
    out = shell("dumpsys device_policy", timeout=120)
    admins: list[dict] = []
    block = re.search(r"Enabled Device Admins.*?(?=\n\s{4}\S|\Z)", out, re.DOTALL)
    if not block:
        return admins
    text = block.group(0)
    current: dict | None = None
    for line in text.splitlines():
        m = re.match(r"\s+([A-Za-z0-9_.]+/[A-Za-z0-9_.]+):\s*$", line)
        if m:
            current = {"admin": m.group(1), "policies": []}
            admins.append(current)
            continue
        if current is not None:
            p = re.match(r"\s+([a-z\-]+)\s*$", line)
            if p and p.group(1) not in ("uid", "testOnlyAdmin"):
                current["policies"].append(p.group(1))
    return admins


def uid_to_package() -> dict[str, str]:
    """uid -> package name, from the bulk package dump."""
    out = shell("dumpsys package packages", timeout=180)
    mapping: dict[str, str] = {}
    for block in re.split(r"\n\s*Package \[", out)[1:]:
        m = re.match(r"([A-Za-z0-9_.]+)\]", block)
        if not m:
            continue
        pkg = m.group(1)
        um = re.search(r"userId=(\d+)", block)
        if um:
            mapping[um.group(1)] = pkg
    return mapping


def device_admin_owners() -> list[str]:
    """Active device admins.

    `dpm list-owners` only reports device/profile OWNERS and can return
    `no owners` even while regular device admins are active — `dumpsys
    device_policy` "Enabled Device Admins" is the source of truth.
    """
    out = shell("dumpsys device_policy", timeout=120)
    admins: list[str] = []
    in_block = False
    for line in out.splitlines():
        if "Enabled Device Admins" in line:
            in_block = True
            continue
        if in_block:
            m = re.match(r"\s+([A-Za-z0-9_.]+/[A-Za-z0-9_.]+):\s*$", line)
            if m:
                admins.append(m.group(1))
            elif admins and line.strip() and not line.startswith("      "):
                break
    return admins


def notification_posters() -> dict[str, int]:
    """package -> number of active notification records."""
    out = shell("dumpsys notification", timeout=150)
    posters: dict[str, int] = {}
    for line in out.splitlines():
        if "NotificationRecord" not in line:
            continue
        m = re.search(r"\bpkg=([A-Za-z0-9_.]+)", line)
        if not m:
            continue
        posters[m.group(1)] = posters.get(m.group(1), 0) + 1
    return posters


def third_party_packages() -> list[dict]:
    """Third-party packages with install/update timestamps, newest first."""
    out = shell("pm list packages -3", timeout=90)
    packages = [l.strip().split(":", 1)[1] for l in out.splitlines() if l.startswith("package:")]

    # One dumpsys for everything, then slice per package.
    dump = shell("dumpsys package packages", timeout=180)

    rows: list[dict] = []
    blocks = re.split(r"\n\s*Package \[", dump)
    for block in blocks[1:]:
        m = re.match(r"([A-Za-z0-9_.]+)\]", block)
        if not m:
            continue
        pkg = m.group(1)
        if pkg not in packages:
            continue

        def field(key: str) -> str:
            mm = re.search(rf"^\s*{key}=(.*)$", block, re.MULTILINE)
            return mm.group(1).strip() if mm else ""

        rows.append(
            {
                "package": pkg,
                "version": field("versionName"),
                "installed": field("firstInstallTime"),
                "updated": field("lastUpdateTime"),
            }
        )

    # Packages missing from the bulk dump (rare) get an individual lookup.
    found = {r["package"] for r in rows}
    for pkg in packages:
        if pkg in found or not valid_pkg(pkg):
            continue
        single = shell(f"dumpsys package {pkg}", timeout=45)

        def sfield(key: str) -> str:
            mm = re.search(rf"^\s*{key}=(.*)$", single, re.MULTILINE)
            return mm.group(1).strip() if mm else ""

        rows.append(
            {
                "package": pkg,
                "version": sfield("versionName"),
                "installed": sfield("firstInstallTime"),
                "updated": sfield("lastUpdateTime"),
            }
        )

    rows.sort(key=lambda r: r["installed"] or "", reverse=True)
    return rows


RISKY = [
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.MANAGE_OWN_CALLS",
    "android.permission.BIND_TELECOM_CONNECTION_SERVICE",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.RECEIVE_BOOT_COMPLETED",
    "android.permission.FOREGROUND_SERVICE",
    "android.permission.USE_FINGERPRINT",
    "android.permission.READ_PHONE_STATE",
    "android.permission.READ_CONTACTS",
    "android.permission.ACCESS_ADSERVICES_TOPICS",
    "android.permission.ACCESS_ADSERVICES_CUSTOM_AUDIENCE",
    "android.permission.ACCESS_ADSERVICES_ATTRIBUTION",
    "android.permission.ACCESS_ADSERVICES_AD_ID",
]


def risky_packages() -> dict[str, list[str]]:
    """package -> risky permissions, from ONE bulk dumpsys."""
    dump = shell("dumpsys package packages", timeout=180)
    out: dict[str, list[str]] = {}
    for block in re.split(r"\n\s*Package \[", dump)[1:]:
        m = re.match(r"([A-Za-z0-9_.]+)\]", block)
        if not m:
            continue
        pkg = m.group(1)
        hits = [p for p in RISKY if p in block]
        if hits:
            out[pkg] = hits
    return out


# --------------------------------------------------------------------------
# report
# --------------------------------------------------------------------------

def full_scan(deep: bool = True) -> dict:
    rep: dict = {"device": device_identity()}
    rep["overlay_window_owners"] = overlay_window_owners()

    if deep:
        rep["overlay_appops"] = overlay_appops()
        rep["accessibility_services"] = accessibility_services()
        rep["notification_listeners"] = notification_listeners()
        rep["device_admin_owners"] = device_admin_owners()
        rep["notification_posters"] = notification_posters()
        rep["risky_packages"] = risky_packages()
        rep["fullscreen_intent_packages"] = fullscreen_intent_packages()
        rep["accessibility_binders"] = accessibility_binders()
        rep["accessibility_history"] = accessibility_history()
        rep["installed_accessibility_services"] = installed_accessibility_services()
        rep["device_admin_details"] = device_admin_details()

        uid_map = uid_to_package()
        holds = wake_lock_holders()
        for h in holds:
            h["package"] = uid_map.get(h["uid"], f"uid:{h['uid']}")
        rep["wake_locks"] = holds

    rep["third_party"] = third_party_packages()
    rep["third_party_count"] = len(rep["third_party"])
    return rep


def render(rep: dict) -> str:
    d = rep["device"]
    L: list[str] = []
    L.append("=" * 70)
    L.append(f"DEVICE : {d['brand']} {d['model']}  |  Android {d['android']} (SDK {d['sdk']})")
    L.append("=" * 70)

    L.append("\n[1] Packages owning a live window (overlay candidates)")
    owners = rep.get("overlay_window_owners") or []
    L.extend([f"    {o}" for o in owners] if owners else ["    (none)"])

    if "overlay_appops" in rep:
        L.append("\n[2] Packages ALLOWED to draw over other apps (SYSTEM_ALERT_WINDOW=allow)")
        appops = rep.get("overlay_appops") or {}
        granted = sorted(
            (p, e) for p, e in appops.items() if isinstance(e, dict) and e.get("mode") == "allow"
        )
        if granted:
            for p, e in granted:
                if e.get("last_draw"):
                    L.append(f"    {p}   last drew {e['last_draw']} (held {e['duration']})")
                else:
                    L.append(f"    {p}   (no overlay drawn in the retained history)")
        else:
            L.append("    (none — no app has an overlay grant)")

        L.append("\n[3] Enabled accessibility services")
        acc = rep.get("accessibility_services") or []
        L.extend([f"    {a}" for a in acc] if acc else ["    (none currently enabled)"])

        installed = rep.get("installed_accessibility_services") or []
        L.append(f"\n[3a] Accessibility services REGISTERED but not enabled ({len(installed)})")
        L.append("      (these can be re-enabled by a boot receiver without asking)")
        L.extend([f"    {s}" for s in installed] if installed else ["    (none)"])

        binders = rep.get("accessibility_binders") or []
        L.append(f"\n[3b] Apps ALLOWED to bind an accessibility service ({len(binders)})")
        L.extend([f"    {p}" for p in binders] if binders else ["    (none)"])

        hist = rep.get("accessibility_history") or []
        if hist:
            writers: dict[str, int] = {}
            for h in hist:
                writers[h["changed_by"]] = writers.get(h["changed_by"], 0) + 1
            L.append(f"\n[3c] Who last wrote the a11y settings ({len(hist)} recorded writes)")
            for w, n in sorted(writers.items(), key=lambda kv: -kv[1]):
                L.append(f"    {n:>3}x  {w}")
            flagged = [h for h in hist if h["service"]]
            if flagged:
                L.append("    services that WERE enabled:")
                for h in flagged:
                    L.append(f"      {h['when']}  {h['service']}  (written by {h['changed_by']})")

        L.append("\n[3c] Notification listeners (can read every notification)")
        listeners = rep.get("notification_listeners") or []
        L.extend([f"    {a}" for a in listeners] if listeners else ["    (none)"])

        L.append("\n[4] Active device admins (dumpsys device_policy — truth source)")
        adm = rep.get("device_admin_owners") or []
        details = {d["admin"]: d.get("policies", []) for d in rep.get("device_admin_details") or []}
        if adm:
            for a in adm:
                pol = ", ".join(details.get(a, []))
                L.append(f"    {a}" + (f"   [{pol}]" if pol else ""))
        else:
            L.append("    (none)")

        fsi = rep.get("fullscreen_intent_packages") or []
        seen_fsi: set[str] = set()
        fsi = [p for p in fsi if not (p in seen_fsi or seen_fsi.add(p))]
        L.append(f"\n[4b] Packages granted USE_FULL_SCREEN_INTENT ({len(fsi)})")
        L.extend([f"    {p}" for p in fsi[:40]] if fsi else ["    (none)"])
        if len(fsi) > 40:
            L.append(f"    ... +{len(fsi) - 40} more")

        L.append("\n[5] Packages posting notifications (active records)")
        posters = rep.get("notification_posters") or {}
        if posters:
            for pkg, n in sorted(posters.items(), key=lambda kv: -kv[1]):
                L.append(f"    {n:>3}  {pkg}")
        else:
            L.append("    (none)")

        L.append("\n[6] Packages with risky / ad-targeting permissions")
        risky = rep.get("risky_packages") or {}
        if risky:
            for pkg, perms in sorted(risky.items()):
                short = [p.rsplit(".", 1)[-1] for p in perms]
                L.append(f"    {pkg}")
                L.append(f"        {', '.join(short)}")
        else:
            L.append("    (none)")

        holds = rep.get("wake_locks") or []
        L.append(f"\n[6b] Wake locks held ({len(holds)})")
        if holds:
            for h in holds:
                L.append(f"    {h.get('package', '?'):<40} {h['lock']}")
        else:
            L.append("    (none)")

    L.append(f"\n[7] Third-party packages ({rep.get('third_party_count', 0)}) — newest first")
    for r in rep.get("third_party") or []:
        L.append(f"    {r['installed']:<22} {r['package']:<45} v{r['version']}")
    return "\n".join(L)


def main() -> int:
    ap = argparse.ArgumentParser(description="Android ad/adware triage over ADB")
    ap.add_argument("--json", action="store_true", help="emit JSON instead of a text report")
    ap.add_argument("--shallow", action="store_true", help="skip the slower dumpsys probes")
    args = ap.parse_args()

    if not device_ok():
        print("[!] No device in 'device' state. Run `adb devices` and reconnect.", file=sys.stderr)
        return 2

    rep = full_scan(deep=not args.shallow)
    print(json.dumps(rep, indent=2, ensure_ascii=False) if args.json else render(rep))
    return 0


if __name__ == "__main__":
    sys.exit(main())
