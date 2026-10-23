# unraid-audit

A kit for letting Claude Code audit, fix and improve an Unraid server **safely**.

- **Health checks and inventory** run freely.
- **Reversible changes** (restart a container, run a scrub, adjust share cache settings…) run after Claude explains them.
- **Dangerous actions** (remove a container, change network/SSH settings, restart the server…) need **two explicit approvals from the owner**.
- **Personal data is never scanned.** Nothing inside shares, array disks or pools is listed, read or measured.

These rules are **enforced in code**, not just written down. The full engagement plan is in [`plan.md`](plan.md). Start there.

---

## How it's enforced

| Layer | File | Runs on | What it does |
|---|---|---|---|
| Server gate | `server/gate.sh` | Unraid (forced command on a dedicated SSH key) | Only named commands with validated arguments. READ / CHANGE / DANGEROUS tiers. No access to share contents or secrets. Automatic config backups. Syslog audit trail. |
| Approval helper | `server/approve.sh` | Unraid (owner's own root session only) | Creates a one-time, 30-minute approval for one exact DANGEROUS request |
| Guard hook | `.claude/hooks/guard.py` | Windows workstation (Claude Code PreToolUse hook) | Default-deny check on every command and file access. Mirrors the gate's allowlist and tiers. Prompts on DANGEROUS. **Fail-closed:** if it can't run, everything is blocked. |
| Permissions | `.claude/settings.json` | Windows workstation (Claude Code) | Ask rules for DANGEROUS. Backstop deny rules (incl. PowerShell/cmd/wsl from Bash). PowerShell tool, sub-agents and MCP tools off. Bypass/auto modes disabled. |
| Self-test | `tests/selftest.sh` | Workstation (Git Bash) | 154 offline checks (incl. a Windows path simulation) that the guards allow, prompt and refuse what they should |

**Workstation:** native Windows with Claude Code and Git for Windows. Claude Code's OS sandbox isn't available on native Windows, so it's off. The guard hook and the server gate carry that job; see `plan.md` §0.1 "Honest limits". For Linux, macOS or WSL2, see [Other platforms](#other-platforms).

**Backups:** the plan tells you to export a flash (OS) backup to another machine before anything else (step 0.1), and again before each day of changes. Claude asks you to confirm it. This is an instruction only; the code doesn't check for it.

---

## Repository layout

```
unraid-audit/
├── README.md                 ← this file
├── plan.md                   ← the step-by-step engagement plan (start here)
├── .claude/
│   ├── settings.json         ← Claude Code permissions and hook registration
│   └── hooks/guard.py        ← client-side guard
├── .github/                  ← branch ruleset + CODEOWNERS (PRs approved by the owner)
├── .gitattributes            ← forces LF line endings (needed on Windows)
├── server/
│   ├── gate.sh               ← server-side gate   → /boot/config/claude-gate/gate.sh
│   └── approve.sh            ← owner approvals    → /boot/config/claude-gate/approve.sh
└── tests/selftest.sh         ← offline self-test
```

The repo contains **no secrets**: no keys, tokens, IPs or backup records. `.gitignore` keeps local state out (`.claude/settings.local.json`, `notes/`).

---

## 1. Set up the Windows workstation (where Claude Code runs)

Run these in **PowerShell** (a normal window, not Administrator). `winget` comes with Windows 10/11.

**1. Install Git for Windows, Python 3 and Claude Code**
```powershell
winget install --id Git.Git -e
winget install --id Python.Python.3.12 -e
winget install --id Anthropic.ClaudeCode -e
```
**Close PowerShell and open a new window** so the new programs are on your PATH. Then check:
```powershell
git --version
py -3 --version            # the guard runs with the "py" launcher, not "python3"
claude --version           # must be 2.1.295 or later (needed for the fail-closed hook)
```
Claude Code needs a Pro, Max, Team, Enterprise or Console account. WinGet installs don't auto-update; update with `winget upgrade Anthropic.ClaudeCode`.

**2. Clone the repo (HTTPS, no SSH key needed) into a non-OneDrive folder**
```powershell
New-Item -ItemType Directory -Force C:\code | Out-Null
cd C:\code
git clone https://github.com/tashey33/unraid-audit.git
cd unraid-audit
```

**3. Run the self-test** (through Git Bash; it runs offline and changes nothing)
```powershell
& "$env:ProgramFiles\Git\bin\bash.exe" tests/selftest.sh
```
The last line must be `passed: 154   failed: 0`.

**4. Find this PC's network IP.** You'll need it for `from=` in plan step 0.4.
```powershell
Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -notmatch 'vEthernet|Loopback' } | Select-Object InterfaceAlias, IPAddress
```
Give this PC a DHCP reservation on your router so the IP doesn't change.

**5. Start Claude Code from inside the folder**
```powershell
cd C:\code\unraid-audit
claude
```
Sign in, then accept the "trust this folder" prompt. Check `/permissions` (the kit's rules are listed) and `/hooks` (the `PreToolUse` guard is listed). **Always start `claude` from this folder.** Started anywhere else, the guard and rules don't load.

If Claude Code says it can't find Git Bash, point it there in PowerShell, then reopen the window:
```powershell
[Environment]::SetEnvironmentVariable("CLAUDE_CODE_GIT_BASH_PATH", "$env:ProgramFiles\Git\bin\bash.exe", "User")
```

**Desktop app instead of the command line?** Open `C:\code\unraid-audit` as the project and run every check in plan step 0.5 there. If any check fails in the app, use the `claude` command line.

**Then follow `plan.md` from step 0.1**: flash backup first, then 0.2 onwards. Steps 0.3 (audit SSH key) and 0.4 (installing the gate) have Windows commands.

---

## 2. Check out on the Unraid server

Unraid needs only the two files in `server/`, installed to `/boot/config/claude-gate/` (the flash drive, so they survive reboots). Two ways to get them:

> ⚠️ **Do the flash backup (plan step 0.1) before this.** Installing writes to the flash drive.
> Run these from **your own root session**: the WebGUI terminal (`>_` icon, top right) or `ssh root@tower`. Never use the audit key.

### Option A — no git needed (recommended)

Unraid has `curl` and `tar`, which is all this needs. Because the repo is private, you need a **read-only token**:

1. On GitHub: **Settings → Developer settings → Personal access tokens → Fine-grained tokens → Generate new token**
   - Repository access: **Only select repositories → `unraid-audit`**
   - Permissions: **Contents → Read-only** (nothing else)
   - Expiration: short, e.g. 7 days
2. On the Unraid server:

```bash
# 1. Enter the token without it being shown or saved in shell history
read -rs -p "GitHub token: " GHTOKEN; echo

# 2. Download the latest version into RAM (/tmp is cleared on reboot) and unpack it
rm -rf /tmp/unraid-audit && mkdir -p /tmp/unraid-audit
curl -fsSL -H "Authorization: Bearer $GHTOKEN" \
  https://api.github.com/repos/tashey33/unraid-audit/tarball/main \
  | tar -xz -C /tmp/unraid-audit --strip-components=1
unset GHTOKEN

# 3. Look before installing: the hashes must match what you reviewed on the workstation
sha256sum /tmp/unraid-audit/server/gate.sh /tmp/unraid-audit/server/approve.sh

# 4. Install to the flash drive
mkdir -p /boot/config/claude-gate
cp /tmp/unraid-audit/server/gate.sh /tmp/unraid-audit/server/approve.sh /boot/config/claude-gate/
sha256sum /boot/config/claude-gate/gate.sh /boot/config/claude-gate/approve.sh
```

What each part does:
- `read -rs` asks for the token with no echo; it stays only in this shell's memory.
- `curl … /tarball/main` downloads a `.tar.gz` of the `main` branch. GitHub's redirect to its download host carries its own short-lived link, so the token isn't forwarded.
- `tar -xz … --strip-components=1` unpacks it, dropping GitHub's `tashey33-unraid-audit-<commit>/` top folder.
- Nothing is written to your shares or array. The download lives in `/tmp` (RAM); only the two scripts are copied to the flash.

Afterwards, revoke the token on GitHub (or let it expire).

### Option B — with git (if `git --version` works on your server)

git isn't part of a stock Unraid install as far as I could confirm; it usually comes from a plugin. If you have it, use a **read-only deploy key** scoped to this one repo:

```bash
# 1. Create a key for this repo only (stored on the flash so it survives reboots)
mkdir -p /boot/config/claude-gate/deploy
ssh-keygen -t ed25519 -N "" -C "unraid-audit deploy (read-only)" -f /boot/config/claude-gate/deploy/id_ed25519
cat /boot/config/claude-gate/deploy/id_ed25519.pub
```
2. On GitHub: **repo → Settings → Deploy keys → Add deploy key**. Paste the public key and leave **"Allow write access" unticked**.
3. Clone into RAM and install:

```bash
export GIT_SSH_COMMAND="ssh -i /boot/config/claude-gate/deploy/id_ed25519 -o IdentitiesOnly=yes"
rm -rf /tmp/unraid-audit
git clone --depth 1 git@github.com:tashey33/unraid-audit.git /tmp/unraid-audit
sha256sum /tmp/unraid-audit/server/*.sh                 # compare with the workstation
mkdir -p /boot/config/claude-gate
cp /tmp/unraid-audit/server/gate.sh /tmp/unraid-audit/server/approve.sh /boot/config/claude-gate/
```

### Option C — copy from the workstation

If the workstation already has the repo, skip GitHub on the server entirely. In PowerShell, in `C:\code\unraid-audit`:

```powershell
ssh root@tower "mkdir -p /boot/config/claude-gate"
scp server/gate.sh server/approve.sh root@tower:/boot/config/claude-gate/
Get-FileHash server\gate.sh, server\approve.sh -Algorithm SHA256
ssh root@tower "sha256sum /boot/config/claude-gate/gate.sh /boot/config/claude-gate/approve.sh"
```
The two sets of hashes must match. PowerShell prints them in upper case; compare the hex digits.

### After installing (any option)

Continue with `plan.md` **step 0.4.3**: bind the audit key to the gate in `/boot/config/ssh/root/authorized_keys`. Then do **0.5**, which proves the guards work.

---

## 3. Updating

1. Change the files on the workstation. If you change the gate's command list, update all three: `server/gate.sh`, `GATE` in `.claude/hooks/guard.py`, and the ask rules in `.claude/settings.json`.
2. Run the self-test (`& "$env:ProgramFiles\Git\bin\bash.exe" tests/selftest.sh`). It must end with `failed: 0`.
3. Commit on a branch, push, and open a pull request (see §4).
4. On Unraid, repeat **Option A/B/C**. Compare the hashes.
5. Ask Claude to run `ssh unraid-audit gate-hash` and confirm it matches the new hash.

Server-specific settings at the top of `gate.sh` (`CRITICAL_NAMES`, `ENABLE_PARITY`, `ENABLE_PLUGINS`, `ENABLE_POWER`) are part of the file. Commit them, so the server copy and the repo stay identical and the hash check stays meaningful.

---

## 4. Change rules for this repository

**No direct commits to `main`.** Every change goes through a pull request and must be approved by the owner (`@tashey33`), including Claude's changes.

| File | Purpose |
|---|---|
| `.github/rulesets/protect-main.json` | Branch ruleset for `main`. Requires a pull request with 1 approval from the code owner. New pushes invalidate earlier approvals, and the latest push must be approved by someone other than the person who pushed it. All review threads must be resolved. Force-pushes and deleting `main` are blocked. |
| `.github/CODEOWNERS` | Makes `@tashey33` the required reviewer for every file |

**Apply the ruleset (owner, once).** GitHub only enforces it after it's applied in the repo settings; the file on its own does nothing.
- *Web:* **Settings → Rules → Rulesets → New ruleset → Import a ruleset** → choose `.github/rulesets/protect-main.json` → **Create**.
- *CLI* (from a checkout, logged in with `gh auth login` as the owner):
  ```bash
  gh api -X POST repos/tashey33/unraid-audit/rulesets --input .github/rulesets/protect-main.json
  ```
- *Check it:* **Settings → Rules → Rulesets** shows `protect-main` as **Active**. A direct `git push origin main` is now rejected.

**How changes flow:**
1. Work on a branch: `git switch -c fix/something`
2. Push it and open a pull request: `git push -u origin fix/something`, then `gh pr create`.
3. **Claude's PRs:** the owner reviews and approves, then merges. Claude can't approve or merge its own PRs.
4. **The owner's own PRs:** GitHub doesn't let anyone approve their own PR. The ruleset therefore lets the repository admin (the owner) bypass the approval **only through a pull request**. You still open a PR and merge it yourself. Nobody, including you, can push straight to `main`.

**Plan note:** on a **private** repo with a free personal account, GitHub may not enforce rulesets. In that case either upgrade to GitHub Pro or make the repo public; the contents are designed to hold no secrets.

---

## 5. Removing everything

From your own root session on Unraid:
- delete the audit key's line from `/boot/config/ssh/root/authorized_keys`
- copy `/boot/config/claude-gate/backups/` somewhere if you want the config history, then `rm -r /boot/config/claude-gate`
- revoke any GitHub token or deploy key you created

On the workstation:
- delete `C:\Users\<you>\.ssh\unraid_audit` and `unraid_audit.pub`, and the `Host unraid-audit` block in `C:\Users\<you>\.ssh\config`
- check that `ssh unraid-audit help` now fails

---

## Other platforms

The kit also runs on Linux, macOS or WSL2, where you can add back Claude Code's OS sandbox as an extra layer. Two edits to `.claude/settings.json`:
1. In the hook, change `"command": "py"` and `"args": ["-3", …]` to `"command": "python3"` and `"args": ["${CLAUDE_PROJECT_DIR}/.claude/hooks/guard.py"]`.
2. Add a `sandbox` block:
   ```json
   "sandbox": {
     "enabled": true, "failIfUnavailable": true, "allowUnsandboxedCommands": false,
     "excludedCommands": ["ssh unraid-audit *"],
     "network": { "allowedDomains": [] },
     "filesystem": { "denyRead": ["~/.ssh", "/mnt", "/boot"] }
   }
   ```
   On Linux/WSL2, install `bubblewrap` and `socat` first. Leave this block out on native Windows: with `failIfUnavailable`, Claude Code refuses to start there.

---

## Status and limits

- Tested offline only: `tests/selftest.sh` (dry-run and temp-folder config edits) on Linux, plus a simulation of the guard's Windows path handling. It hasn't been run on a real Windows PC or against a live Unraid server yet. Plan steps 0.5–0.6 are the first live checks.
- No OS sandbox on native Windows (see `plan.md` §0.1).
- Parity, plugin and restart/power-off commands ship **switched off** until their syntax is confirmed on your Unraid version (plan 0.6k).
- Direct `.cfg` edits may not take effect until Unraid reloads them. Plan 0.6l tests this once.
- See "Honest limits" in `plan.md` §0.1 for the rest.
