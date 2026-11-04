#!/usr/bin/env python3
"""
Fingerprint an Android package for ad-SDK / adware indicators using only ADB.

Usage:
    python apk_scan.py <package.name> [--pull]

Works on any host with adb on PATH (Windows / macOS / Linux). No root, no
aapt, no apktool required - the analysis is done on the raw APK bytes.

What it reports:
  * component names declared in the manifest (activities/services/receivers)
  * ad-SDK class markers found in classes.dex
  * high-risk requested permissions (from `dumpsys package`)

Exit codes: 0 = ok, 1 = package not found, 2 = adb/device error.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

# Markers that identify a bundled advertising / analytics SDK.
AD_SDK_MARKERS = {
    "Google Mobile Ads (AdMob)": ["com/google/android/gms/ads", "com.google.android.gms.ads"],
    "Unity Ads": ["com/unity3d/ads", "com.unity3d.ads"],
    "AppLovin": ["com/applovin", "com.applovin.sdk"],
    "Vungle / Liftoff": ["com/vungle", "com.vungle.ads"],
    "IronSource": ["com/ironsource", "com.ironsource.mediationsdk"],
    "AdColony": ["com/adcolony", "com.adcolony.sdk"],
    "Mintegral": ["com/mbridge", "com.mbridge.msdk"],
    "Chartboost": ["com/chartboost", "com.chartboost.sdk"],
    "Fyber / Inneractive": ["com/fyber", "com.inneractive"],
    "InMobi": ["com/inmobi", "com.inmobi.sdk"],
    "Mopub": ["com/mopub", "com.mopub.ads"],
    "Taboola / Outbrain": ["com/taboola", "com.taboola.android"],
    "Bigo Ads": ["sg/bigo/ads", "sg.bigo.ads"],
    "Huawei AppGallery ads": ["com/huawei/hms/ads"],
    "StartApp": ["com/startapp", "com.startapp.sdk"],
    "AdMob mediation (pangle)": ["com/bytedance/sdk/openadsdk", "com.bytedance"],
    "Yandex ads": ["com/yandex/mobileads"],
    "Smaato": ["com/smaato", "com.smaato.sdk"],
}

# Permissions that give an app the ability to harass the user or escalate.
RISKY_PERMISSIONS = {
    "android.permission.SYSTEM_ALERT_WINDOW": "draw over other apps (ad overlay)",
    "android.permission.MANAGE_OWN_CALLS": "manage own calls",
    "android.permission.BIND_TELECOM_CONNECTION_SERVICE": "telecom connection (high privilege)",
    "android.permission.REQUEST_INSTALL_PACKAGES": "install other APKs",
    "android.permission.POST_NOTIFICATIONS": "post notifications (ad pushes)",
    "android.permission.RECEIVE_BOOT_COMPLETED": "auto-start at boot",
    "android.permission.FOREGROUND_SERVICE": "foreground service (persistent overlay)",
    "android.permission.ACCESS_ADSERVICES_TOPICS": "ad topics (targeting)",
    "android.permission.ACCESS_ADSERVICES_CUSTOM_AUDIENCE": "custom ad audiences",
    "android.permission.ACCESS_ADSERVICES_ATTRIBUTION": "ad attribution",
    "android.permission.USE_FINGERPRINT": "fingerprint",
    "android.permission.READ_PHONE_STATE": "device identifiers",
    "android.permission.READ_CONTACTS": "contacts (push target list)",
    "android.permission.SYSTEM_ALERT_WINDOW": "draw over other apps",
}


# Package names are interpolated into `adb shell` strings. Restrict them to
# the characters Android actually allows so a crafted name can never become
# a second shell command on the device.
PKG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._]{0,254}$")


def sh(args: list[str], timeout: int = 60) -> str:
    try:
        out = subprocess.run(
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
    return out.stdout


def manifest_strings(data: bytes) -> list[str]:
    """Pull printable UTF-16LE runs out of a binary AndroidManifest.xml."""
    text = data.decode("utf-16-le", errors="ignore")
    runs = re.findall(r"[\x20-\x7e]{5,}", text)
    seen: list[str] = []
    for r in runs:
        if r not in seen:
            seen.append(r)
    return seen


def dex_strings(data: bytes) -> str:
    """Best-effort text view of a dex file (MUTF-8 is readable as latin-1)."""
    return data.decode("latin-1", errors="ignore")


def scan_package(pkg: str, do_pull: bool) -> int:
    if not PKG_RE.match(pkg):
        print(f"[!] '{pkg}' is not a valid Android package name")
        return 1

    paths = [
        line.strip()
        for line in sh(["shell", "pm", "path", pkg]).splitlines()
        if line.strip().startswith("package:")
    ]
    if not paths:
        print(f"[!] package '{pkg}' not found on device")
        return 1

    print("=" * 70)
    print(f"PACKAGE: {pkg}")
    print("=" * 70)

    # ---- permissions -------------------------------------------------
    dump = sh(["shell", "dumpsys", "package", pkg])
    print("\n-- requested permissions (ad/harassment relevant) --")
    hits = 0
    for perm, why in sorted(RISKY_PERMISSIONS.items()):
        if perm in dump:
            granted = "granted=true" in dump.split(perm, 1)[1][:200]
            print(f"  [!] {perm}\n        {why}  (granted={granted})")
            hits += 1
    if not hits:
        print("  (none of the known risky permissions requested)")

    # ---- install metadata --------------------------------------------
    print("\n-- install metadata --")
    for line in dump.splitlines():
        s = line.strip()
        if s.startswith(("versionName=", "firstInstallTime=", "lastUpdateTime=", "codePath=")):
            print(f"  {s}")

    if not do_pull:
        print("\n(re-run with --pull to extract manifest components and dex markers)")
        return 0

    # ---- pull and analyse --------------------------------------------
    with tempfile.TemporaryDirectory(prefix="apkscan_") as tmp:
        tmpdir = Path(tmp)
        for remote in paths:
            remote = remote[len("package:") :]
            local = tmpdir / remote.rsplit("/", 1)[-1]
            r = subprocess.run(
                ["adb", "pull", remote, str(local)],
                capture_output=True,
                text=True,
                errors="replace",
                shell=False,
            )
            if r.returncode != 0:
                print(f"  [warn] pull failed for {remote}")
                continue

            try:
                with zipfile.ZipFile(local) as z:
                    names = z.namelist()

                    if "AndroidManifest.xml" in names:
                        comps = [
                            s
                            for s in manifest_strings(z.read("AndroidManifest.xml"))
                            if s.startswith(pkg + ".") or "/" in s and s.startswith("com.")
                        ]
                        comps = [c for c in comps if c.count(".") <= 6 and " " not in c]
                        print(f"\n-- manifest components ({local.name}) --")
                        for c in comps[:60]:
                            print(f"  {c}")
                        if len(comps) > 60:
                            print(f"  ... +{len(comps) - 60} more")

                    dexes = [n for n in names if n.startswith("classes") and n.endswith(".dex")]
                    if dexes:
                        blob = "".join(dex_strings(z.read(n)) for n in dexes)
                        print(f"\n-- ad SDK markers ({', '.join(dexes)}) --")
                        found = False
                        for sdk, markers in AD_SDK_MARKERS.items():
                            for m in markers:
                                if m in blob:
                                    print(f"  [!] {sdk}  ({m})")
                                    found = True
                                    break
                        if not found:
                            print("  (no known ad SDK markers found)")
            except zipfile.BadZipFile:
                print(f"  [warn] {local.name} is not a readable zip")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Fingerprint an Android package for ad-SDK indicators")
    ap.add_argument("package")
    ap.add_argument("--pull", action="store_true", help="pull the APK and analyse manifest + dex")
    args = ap.parse_args()

    devices = sh(["devices"])
    if "device\n" not in devices.replace("\r\n", "\n"):
        print("[!] no device in 'device' state. Check `adb devices`.")
        return 2

    return scan_package(args.package, args.pull)


if __name__ == "__main__":
    sys.exit(main())
