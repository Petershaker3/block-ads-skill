// block-ads — OpenCode plugin (V2 API).
//
// Two jobs:
//   1. Register an `ads.scan` tool so the agent can run the ad/adware triage
//      in one call instead of hand-assembling a dozen adb commands.
//   2. Auto-attach the `block-ads` skill whenever the prompt talks about ads,
//      overlays, adware, notification spam, or a device that hangs / loses
//      touch — so the procedure is always applied, not just when remembered.
//
// The skill in ~/.config/opencode/skills/block-ads/SKILL.md is the source of
// truth for the procedure. This plugin only wires it into the runtime.
//
// Installed at ~/.config/opencode/plugins/block-ads/index.mjs; the global
// plugins directory is auto-discovered by OpenCode V2, so no config entry is
// required.

import { execFile } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

const configHome = process.env.XDG_CONFIG_HOME || path.join(os.homedir(), ".config");
const skillDir = path.join(configHome, "opencode", "skills", "block-ads");
const scriptPath = path.join(skillDir, "scripts", "device_scan.py");
const alwaysOnPath = path.join(configHome, "opencode", "plugins", "block-ads", "always-on.md");

const SKILL_ID = "block-ads";

const TRIGGER =
  /\b(ads?|adwares?|ad-?ware|popup|pop-?ups?|overlay|notification spam|fullscreen ad)\b|إعلانات|الإعلانات|اعلانات|宣告|شيل الإعلانات|منع الإعلانات|إزالة الإعلانات|التاتش مش شغال|الجهاز معلق|تقفل الشاشة/i;

const OFF_SWITCH =
  /\b(stop ads mode|exit ads mode|ads mode off)\b|اقفل mode الإعلانات|وقف وضع الإعلانات|منع الإعلانات off/i;

// Sessions where ads mode was switched on by the user.
const activeSessions = new Set();

function readOrEmpty(file) {
  try {
    return fs.readFileSync(file, "utf8");
  } catch {
    return "";
  }
}

function stripFrontmatter(text) {
  return text
    .replace(/^---[^\S\r\n]*\r?\n[\s\S]*?\r?\n---[^\S\r\n]*(?:\r?\n|$)/, "")
    .replace(/(?:\r?\n)+$/, "");
}

function pythonCommand() {
  return process.platform === "win32" ? "python" : "python3";
}

async function runScan(extraArgs) {
  const { stdout, stderr } = await execFileAsync(pythonCommand(), [scriptPath, ...extraArgs], {
    maxBuffer: 32 * 1024 * 1024,
    timeout: 180_000,
    windowsHide: true,
  });
  const out = stdout.trim();
  const err = stderr.trim();
  return err ? `${out}\n\n[stderr]\n${err}`.trim() : out || "(no output)";
}

export default {
  id: "block-ads",
  async setup(ctx) {
    const ruleset = stripFrontmatter(readOrEmpty(alwaysOnPath));

    // --- auto-attach the skill on ad-related prompts -----------------------
    await ctx.session.hook("prompt", (event) => {
      const text = event?.prompt?.text ?? "";
      const sessionID = event?.sessionID ?? "";

      if (OFF_SWITCH.test(text)) {
        activeSessions.delete(sessionID);
        return;
      }

      const shouldAttach = TRIGGER.test(text) || activeSessions.has(sessionID);
      if (!shouldAttach) return;

      if (sessionID) activeSessions.add(sessionID);

      const prompt = event.prompt;
      prompt.skills ??= [];
      if (!prompt.skills.some((s) => s?.id === SKILL_ID)) {
        prompt.skills.push({ id: SKILL_ID });
      }
    });

    // --- always-on ruleset for turns in an ads-mode session ----------------
    if (ruleset) {
      await ctx.session.hook("context", (event) => {
        const sessionID = event?.sessionID ?? "";
        if (!sessionID || !activeSessions.has(sessionID)) return;

        const system = event.system || (event.system = []);
        const last = system[system.length - 1];
        const block =
          "AD-BLOCK MODE ACTIVE (block-ads plugin). The ruleset below applies to " +
          "every turn in this session until the user says \"stop ads mode\". It says " +
          "how to find the package that owns the ads and how to remove it safely.\n\n" +
          ruleset;
        if (last && last.type === "text" && typeof last.text === "string") {
          last.text += "\n\n" + block;
        } else {
          system.push({ type: "text", text: block });
        }
      });
    }

    // --- ads.scan tool ------------------------------------------------------
    await ctx.tool.transform((editor) => {
      editor.namespace({
        name: "ads",
        description: "Android ad / adware triage over ADB (no root).",
      });

      editor.add({
        name: "scan",
        description:
          "Scan the connected Android device for ad sources: overlay window owners, " +
          "SYSTEM_ALERT_WINDOW grants, enabled accessibility services, device admin " +
          "owners, notification spammers, and third-party packages with install dates. " +
          "Use this before removing any ad-related app. Args: json (emit JSON), " +
          "shallow (skip slow per-package probes).",
        input: {
          type: "object",
          properties: {
            json: {
              type: "boolean",
              description: "Return raw JSON instead of the text report.",
            },
            shallow: {
              type: "boolean",
              description: "Skip the slow per-package appop and dumpsys probes.",
            },
          },
          required: [],
          additionalProperties: false,
        },
        options: { namespace: "ads" },
        execute: async (input) => {
          const args = [];
          if (input?.json) args.push("--json");
          if (input?.shallow) args.push("--shallow");
          try {
            const report = await runScan(args);
            return {
              content: [
                {
                  type: "text",
                  text:
                    "Ad-source triage report. Identify the offending package from this " +
                    "output, confirm with the user, then apply the block-ads skill " +
                    "procedure. Do not uninstall without confirmation.\n\n" +
                    report,
                },
              ],
            };
          } catch (err) {
            return {
              content: [
                {
                  type: "text",
                  text:
                    "Ad-source scan failed: " +
                    (err instanceof Error ? err.message : String(err)) +
                    "\nCheck `adb devices` — the device must be in 'device' state.",
                },
              ],
            };
          }
        },
      });
    });
  },
};
