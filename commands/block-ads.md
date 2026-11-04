---
description: Scan the connected Android device for ad sources (overlay owners, ad notifications, adware packages) and remove them
---

Use the `block-ads` skill for this task. Load it with the skill tool using id `block-ads` and follow it exactly.

$ARGUMENTS

Steps to follow:

1. Run the ad-source triage scan over ADB and identify the offending package.
2. Show the evidence: package name, install date, risky permissions.
3. Ask the user before removing anything.
4. Apply the matching fix (revoke overlay grant / disable ad notifications / block DNS / uninstall the adware app).
5. Re-verify and report the result.
