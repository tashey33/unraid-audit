# Unraid Server Audit, Fix & Improve — Engagement Plan

## What's in this kit

```
unraid-audit/
├── plan.md                    ← this file
├── .claude/
│   ├── settings.json          ← Claude Code permissions and hook registration
│   └── hooks/guard.py         ← client-side guard (runs before every Claude command)
├── server/gate.sh             ← server-side gate (owner installs on the Unraid flash)
├── server/approve.sh          ← owner-only helper that approves one dangerous action
└── tests/selftest.sh          ← proves both guards allow/prompt/deny what they should (offline)
```

---

## 0. Ground rules

1. **Backup first.** Before anything else — including installing the gate — the owner exports a backup of the Unraid OS (the flash drive) to another machine (step 0.1). **Enforced in code:** until the owner records the backup, the guard and the gate refuse every server command except `help`.
2. **Three tiers of action, enforced in code:**

   | Tier | Examples | What's required |
   |---|---|---|
   | **READ** | health check, hardware inventory, config review | Nothing extra. Pre-approved by the owner. |
   | **CHANGE** (reversible) | start/stop/restart a container or VM, VM autostart, SMART self-test, scrub, run the mover, non-correcting parity check, safe share settings (cache/pool use, allocation, split level, include/exclude, floor, comment) | Claude may do these **without asking each time**, but only when the flash backup is less than 24 hours old. Config edits save an automatic backup copy first and print the undo command. |
   | **DANGEROUS** (destructive, hard to undo, or can lock people out) | remove a container, prune images, force-stop a VM, share security/export settings, any top-level config edit (network, SSH, WebGUI, Docker, VM settings), restoring a non-share config, correcting parity check, plugin install/update/remove, server restart/power-off | **Explicit owner permission, twice:** (a) a Claude Code permission prompt you must approve, and (b) a one-time approval you create on the server for that *exact* action with `approve.sh`. It expires after 30 minutes, works once, and still needs the backup to be < 24 h old. |
   | **NEVER** via Claude | format/wipe/partition, New Config, disk assignment, filesystem repair, array start/stop, OS upgrade, reading or deleting anything inside shares/disks/pools | Not implemented in the gate at all. The owner does these by hand. |

3. **Explain before acting.** Before every CHANGE or DANGEROUS action Claude states what it does, why, the impact and downtime, and how to undo it. For DANGEROUS actions it then waits for the owner to approve.
4. **Do not scan personal data.** No listing, reading, searching or measuring the contents of shares, array disks or pools, and no reading raw disks. Hardware, health and configuration information is allowed.
5. **One change at a time, verify, log.** After each change Claude re-runs the read command that shows the result. If something is wrong it rolls back (e.g. `cfg-restore`) and stops.
6. **Don't expose secrets; stop on surprises.** Password/key-type settings can't be read or changed through the gate.

### 0.1 How the rules are enforced (in code, not by request)

Instructions in a plan only shape what Claude tries to do. These layers decide what it **can** do. Each one works even if the others fail.

**Workstation: native Windows.** Claude Code is installed with `winget` (or the Desktop app), and Git for Windows provides the Bash shell Claude uses. Claude Code's OS sandbox doesn't exist on native Windows, so layer 3 is **off**; the other three are on.

| # | Layer | Where it runs | What it enforces | Can Claude change it? |
|---|---|---|---|---|
| 1 | **Server gate** (`server/gate.sh`) bound to the audit SSH key as a *forced command* with `restrict` | Unraid server, enforced by sshd | Whatever Claude sends, sshd runs the gate instead. The gate accepts only its named READ/CHANGE/DANGEROUS commands with validated arguments. There is no command that touches `/mnt` contents, raw disks or password/key files, and NEVER-tier actions aren't implemented. Secrets are redacted. CHANGE and DANGEROUS need the backup marker to be < 24 h old. DANGEROUS also needs a one-time, unexpired approval file that only `approve.sh` (run by the owner) creates; it's consumed on use. Config edits are backed up automatically. Forwarding and shells are disabled. Every request is logged to syslog (`claude-gate`: ALLOW / DENY / APPROVAL-USED / CHANGED). | No — no gate command writes to the gate, `approve.sh`, the approvals folder or the backup marker |
| 2 | **Guard hook** (`.claude/hooks/guard.py`) | Workstation, run by Claude Code before every Bash/file tool call | Default-deny. Bash may only run `ssh unraid-audit <gate-command>` (same allowlist and tiers as the gate) or simple local text tools. No ssh options, other hosts, pipes after ssh, `;` `&&` redirects or substitutions. Refuses CHANGE/DANGEROUS when `.claude/backup-confirmed` is > 24 h old. Asks Claude Code to prompt the owner for every DANGEROUS call. File tools can't read `/mnt`, `/dev`, secrets or `~/.ssh` (`C:\Users\<you>\.ssh`), and can't write outside the project or into `.claude/`. Registered with `onFailure: "block"`: if Python is missing, the script can't start, crashes or times out, every guarded call is **refused**, not allowed. Understands Windows (`C:\…`) and Git Bash (`/c/…`) paths. | No — writes to `.claude/` are blocked |
| 3 | **Sandbox** (OS-level) | — | **Not available on native Windows.** On Linux, macOS or WSL2 it can be switched back on (README "Other platforms"). Without it, local commands aren't network- or filesystem-isolated by the OS; the guard hook's default-deny list (only `ssh unraid-audit …` and a few text tools) carries that job. | — |
| 4 | **Permission rules** (`settings.json`) | Workstation, enforced by Claude Code | `ssh unraid-audit *` is allowed. **Ask rules force a permission prompt for every DANGEROUS gate command.** Ask beats allow, and choosing "don't ask again" can't turn the prompt off. Backstop deny list (local destructive commands, `/mnt` paths, secrets, `approve.sh`, `scp`/`rsync`/`curl`, interpreters, local `docker`/`virsh`). Removes PowerShell (also switched off via `CLAUDE_CODE_USE_POWERSHELL_TOOL=0`), sub-agents and MCP tools. Denies `powershell`, `pwsh`, `cmd.exe`, `wsl`, `reg` and `schtasks` from Bash. Bypass and auto modes disabled, so prompts can't be skipped. | No — `.claude/` is protected |

**Honest limits**
- Layers 2 and 4 only apply to Claude Code on the workstation. Layer 1 is the real boundary: it holds even if the workstation side is misconfigured.
- **No OS sandbox on native Windows.** If something got past the guard hook (a bug, or a Claude Code version that ignores hooks), a local command would run with your normal Windows permissions. The gate still limits what can reach the server.
- The hook fails closed (`onFailure: "block"`, needs Claude Code v2.1.295 or later). If the hook isn't registered at all, e.g. Claude Code was started outside the project folder, it doesn't run. Step 0.5 proves it's active.
- **Desktop app:** the kit is set up and tested for the `claude` command line. If you use the Desktop app instead, open this folder as the project and run every step-0.5 check there too. If any check fails in the Desktop app, use the command line.
- The gate protects the **audit key only**. Any other root key or password login bypasses it (that's the owner's access). Step 0.6d lists every key so the owner can decide.
- The DANGEROUS-tier server approval is only as strong as the owner's own access: anyone with a root session on the server can run `approve.sh`. Claude has no root session other than the gated audit key.
- Editing a `.cfg` file isn't always enough for Unraid to apply the setting. Some settings are held in memory and only take effect, or get rewritten, when the matching WebGUI page or service reloads them. Claude verifies every config change, and if a change doesn't take, the owner applies it in the WebGUI. Step 0.6l tests this once on a harmless setting.
- Docker template XML files can contain app passwords, so the gate only lists their names. The system log can mention file names, so Claude reads it for errors only and doesn't record file names.

---

## 1. Pre-engagement

Confirm with the owner: Unraid version, existing backups, maintenance windows (when CHANGE actions that cause downtime — container/VM restarts, scrubs, SMART long tests — are acceptable), known issues, critical containers/VMs that must not be restarted without asking, and who approves DANGEROUS actions. Already agreed:
- health check and inventory are pre-approved
- Claude may make reversible changes
- dangerous or destructive actions need explicit permission
- personal data is not to be scanned; hardware info is fine

The containers/VMs the owner names as critical go into `CRITICAL_NAMES` at the top of `gate.sh` before it's installed. The gate then treats starting, stopping, restarting or changing autostart for them as DANGEROUS (server approval required). For the matching Claude Code prompt, also add an ask rule per name to `settings.json`, e.g. `"Bash(ssh unraid-audit docker-* homeassistant)"`.

---

## Phase 0 — Initialize (first connection; complete in order, nothing else first)

### 0.1 Back up the OS to a remote machine (owner) — BEFORE ANYTHING ELSE

The Unraid OS and all of its configuration live on the boot flash drive: license key, disk assignments, shares, users, network, Docker templates, plugins. Back it up to **a different machine** (laptop, desktop, NAS or cloud — not this server's array) before any other step, because step 0.4 writes to the flash.

Claude doesn't perform or see this backup. It contains password hashes and keys, and the gate deliberately has no command that can read it.

**Method A — WebGUI (recommended)**
1. On the remote machine, open the Unraid WebGUI in a browser.
2. **Main** → click the flash device (listed under *Boot Device*) → **Flash Backup**.
3. A zip file downloads to that machine.

**Method B — command line from the remote machine** (owner's own terminal and normal root login — not the audit key, which the gate would refuse)
```bash
mkdir -p ~/unraid-backups
ssh root@tower "tar -C /boot -czf - ." > ~/unraid-backups/unraid-flash-$(date +%F).tar.gz
```
- `ssh root@tower "…"` runs the quoted command on the server.
- `tar -C /boot -czf - .` packs the whole flash drive into a compressed archive and writes it to the connection instead of a file, so **nothing is written on the server**.
- `> ~/unraid-backups/…` saves the stream on the remote machine with today's date in the name.
- Avoid making config changes while it runs, so the copy is consistent.

**Method C — Unraid Connect automated flash backup (optional extra, not a substitute).** It's stored in the cloud, keeps only the latest copy, and excludes passwords (`config/shadow`, `config/smbpasswd`) and WireGuard keys.

**Export & verify (do all of these)**
1. **Check the contents:** `unzip -l <file>.zip` or `tar -tzf <file>.tar.gz | less`. Confirm there's a `config/` folder, a license key file (`config/*.key`), `config/super.dat` (disk assignments), `config/shares/` and the boot files (`bz*`).
2. **Checksum:** Windows PowerShell: `Get-FileHash <file> -Algorithm SHA256 | Format-List > <file>.sha256.txt` (Linux: `sha256sum <file> > <file>.sha256`).
3. **Second copy:** copy the file and its `.sha256` to a second location that isn't this server (another drive, NAS or cloud). That gives 3 copies: the flash and two exports.
4. **Protect it:** it holds password hashes, SSH/WireGuard keys and the license. Encrypt it (e.g. a password-protected 7-Zip archive with AES-256) and keep it out of shared folders. On Windows, don't leave an unencrypted copy in a OneDrive/Dropbox-synced folder.
5. **Record the disk map:** screenshot or print the **Main** tab showing each disk's slot, model and serial. Restoring an old backup after disks have been reassigned can overwrite data, so you need to know which disk was where.
6. **Record it on the server** (creates the gate's marker file; do this after step 0.4 has created the folder, or create the folder now):
   ```bash
   mkdir -p /boot/config/claude-gate
   echo "$(date -Is) file=<name> sha256=<hash> copies=<where> unraid=$(cat /etc/unraid-version)" > /boot/config/claude-gate/BACKUP-CONFIRMED
   ```
7. **Record it on the workstation** (unlocks the guard hook). In PowerShell, in the project folder:
   ```powershell
   "$(Get-Date -Format s) file=<name> sha256=<hash> copies=<where>" | Set-Content .claude\backup-confirmed
   ```
   Re-running this command refreshes the 24-hour clock.

**Restore notes (for reference)**
- *Same flash drive is fine:* use the Unraid **USB Flash Creator** with the **Local Zip** option, or format the stick FAT32, label it `UNRAID`, extract the backup onto it and run `make_bootable` (`.bat` on Windows) as administrator.
- *New flash drive:* the license is tied to the drive's GUID. Unraid asks for a license transfer on first boot, and the old drive gets blacklisted.
- *Unraid Connect backup:* afterwards you must reset user passwords and regenerate WireGuard keys.
- **Backup freshness is enforced:** CHANGE and DANGEROUS actions are refused once the backup record is more than 24 hours old. Before each day of changes, repeat 0.1 and refresh both records (server: re-run step 6; workstation: re-run step 7). READ commands keep working with an older backup.

### 0.2 Prepare the workstation (owner, Windows)
The exact PowerShell commands are in **README §1**. In summary:
1. Install **Git for Windows**, **Python 3** and **Claude Code** with `winget`. Open a new PowerShell window afterwards.
2. Clone the repo **over HTTPS** into a normal folder, e.g. `C:\code\unraid-audit`. Avoid OneDrive-synced folders: syncing can lock files and would copy your backup record around.
3. Run the self-test through Git Bash. All checks must pass. It runs offline and changes nothing.
4. Start `claude` **inside** the folder, sign in, and accept the workspace-trust prompt. Then check:
   - `/permissions` lists the rules from `.claude/settings.json`.
   - `/hooks` shows the `PreToolUse` guard (`py -3 …guard.py`, on failure: block).
   - `claude --version` is 2.1.295 or later, which `onFailure` needs.

### 0.3 Create the audit key and SSH alias (owner, on the workstation)
In PowerShell (Windows 10/11 include OpenSSH):
```powershell
ssh-keygen -t ed25519 -f $HOME\.ssh\unraid_audit -C claude-audit
notepad $HOME\.ssh\config
```
This creates a key pair used only by Claude. Press Enter twice for no passphrase. Git Bash, which Claude uses, reads the same `C:\Users\<you>\.ssh` folder.

Add to the config file and save it **without** a `.txt` extension:
```
Host unraid-audit
    HostName 192.168.1.10        # the server's IP
    User root
    IdentityFile ~/.ssh/unraid_audit
    IdentitiesOnly yes           # never offer the owner's other keys
    BatchMode yes                # never prompt for a password
    PasswordAuthentication no
    ForwardAgent no
    ClearAllForwardings yes
    RequestTTY no
    ControlMaster no
```

### 0.4 Install the gate on the server (owner — writes to the flash, so only after 0.1)
1. Edit the settings at the top of `server/gate.sh` first:
   - `CRITICAL_NAMES` — containers/VMs that need approval to start/stop.
   - Leave `ENABLE_PARITY`, `ENABLE_PLUGINS` and `ENABLE_POWER` at `0` for now (step 0.6k).
   - Optionally adjust `MAX_BACKUP_AGE_H` (24) and `APPROVAL_TTL_MIN` (30).
   Re-run the self-test.
2. Copy the gate and the approval helper to the server. Either check them out from GitHub directly on Unraid (README §2, Option A or B), or copy them from the workstation (PowerShell, in the repo folder):
   ```powershell
   ssh root@tower "mkdir -p /boot/config/claude-gate"
   scp server/gate.sh server/approve.sh root@tower:/boot/config/claude-gate/
   Get-FileHash server\gate.sh, server\approve.sh -Algorithm SHA256              # note the hashes
   ssh root@tower "sha256sum /boot/config/claude-gate/gate.sh /boot/config/claude-gate/approve.sh"   # must match (same hex, lower-case)
   ```
   If the hashes differ, the files were checked out with Windows line endings. The repo's `.gitattributes` prevents this; re-clone if it happens.
3. Bind the audit key to the gate. Append **one line** to `/boot/config/ssh/root/authorized_keys`, which persists on the flash; on Unraid 6.9+ `/root/.ssh` is a symlink to it:
   ```
   restrict,from="<workstation-IP>",command="/bin/bash /boot/config/claude-gate/gate.sh" <contents of C:\Users\<you>\.ssh\unraid_audit.pub>
   ```
   - `command=` forces the gate whatever the client asks for.
   - `restrict` turns off port/agent/X11 forwarding and terminals.
   - `from=` only accepts the key from the Windows PC's network IP (README §1 shows how to find it). Give the PC a DHCP reservation so it doesn't change.
4. Make sure the backup marker from 0.1 step 6 exists.

**How you approve a DANGEROUS action later.** From your own root session — the WebGUI terminal, or `ssh -t root@tower` with your normal login, never the audit key:
```bash
bash /boot/config/claude-gate/approve.sh docker-remove plex    # approve exactly this, once, for 30 min
bash /boot/config/claude-gate/approve.sh --list                # see pending approvals
bash /boot/config/claude-gate/approve.sh --revoke-all          # cancel all pending approvals
```
`approve.sh` shows the exact action and asks you to type `YES`. The approval only matches that exact command and arguments, works once, and expires.

### 0.5 Prove the guards work before Claude connects (owner)
From your own PowerShell window (bypassing Claude, to test the server on its own):

| Test | Expected |
|---|---|
| `ssh unraid-audit help` | List of gate commands |
| `ssh unraid-audit` | `DENIED - interactive shells are not allowed` |
| `ssh unraid-audit 'ls /mnt/user'` | `DENIED` |
| `ssh unraid-audit 'uptime; reboot'` | `DENIED - disallowed characters` |
| `ssh -L 8080:localhost:80 unraid-audit help` | Help prints, but the port forward is refused |
| `ssh unraid-audit docker-image-prune` | `DENIED - DANGEROUS action needs the owner's one-time approval` |
| `ssh unraid-audit server-restart` | `DENIED - … switched off` |
| `ssh unraid-audit format /dev/sda` | `DENIED - unknown command` (NEVER tier) |
| `ssh root@tower "grep claude-gate /var/log/syslog \| tail"` | `ALLOW`/`DENY` lines for the tests above |

Then in Claude Code (started from inside the repo folder):
- Ask Claude to run `ls /mnt`. It must come back **"BLOCKED by audit guard"**.
- Ask Claude to run `powershell -c dir`. It must be **blocked**.
- Ask Claude to read `C:\Users\<you>\.ssh\unraid_audit`. It must be **blocked**.
- Ask Claude to run `ssh unraid-audit docker-image-prune`. Claude Code must show you a **permission prompt**. Answer **No**.
- **Fail-closed check:** temporarily rename `.claude\hooks\guard.py` to `guard.py.off` in Explorer. Ask Claude to run `ls`. It must be **blocked**, with a hook-failure message. Rename the file back.

If any check fails, a workstation guard isn't active: stop and fix that first.

### 0.6 First connection by Claude — close the known gaps (pre-approved, read-only)

| Step | Gate command | Gap it closes |
|---|---|---|
| a | `gate-hash` (and locally `sha256sum server/gate.sh`) | Confirms the installed gate is exactly the reviewed file. Mismatch → stop. |
| b | `version`, `ssh-version` | Unraid ≥ 6.9 (key persistence via `/boot/config/ssh/root`) and OpenSSH new enough for `restrict` (≥ 7.2). |
| c | `paths-check` | Resolves every path the plan assumes (`var.ini`, `disks.ini`, `*.cfg`, `go`, templates, logs), confirms `/root/.ssh` → `/boot/config/ssh/root`, and records which secret files exist — without reading them. |
| d | `authkeys-summary` | Lists every key allowed to log in as root (type, options and comment only). The audit key must show `HAS-OPTIONS [bound to claude-gate]`. Other keys without options have full root access — the owner decides whether to keep them. |
| e | `sshd-auth` | Is password login enabled? Is forwarding allowed? (Feeds the security audit.) |
| f | `tools-check` | Which inventory tools exist (`nvme`, `sensors`, `zpool` …). Missing ones are dropped from Phase 1. |
| g | `mounts` | Pool names, including custom names. The gate and guard refuse all `/mnt` content by design, so custom pools need no extra rules. The names are recorded for `btrfs-usage`/`btrfs-stats`. |
| h | `lsblk` | Device names match the gate's device pattern (`/dev/sdX`, `/dev/sdXY`, `/dev/nvmeN[nM]`). If not, the owner extends the pattern in both files. |
| i | `ls-config`, `ls-shares` | Confirms share names fit the allowed name pattern (letters, digits, `_ . -`). Shares with spaces need an owner edit to the gate. |
| j | `syslog-tail 50` | Confirms gate logging works. |
| k | `tools-check` (owner checks usage text) | **Switched-off commands.** I couldn't confirm the current Unraid syntax for `mdcmd check NOCORRECT` / `CORRECT` / `mdcmd nocheck` (parity), `plugin install` / `update` / `remove`, or `powerdown -r` (restart), so these ship disabled. The owner confirms each on this Unraid version (e.g. run the tool without arguments from their own session to see its usage), then sets `ENABLE_PARITY` / `ENABLE_PLUGINS` / `ENABLE_POWER` to `1`, reinstalls and re-hashes. `mover start` is confirmed for Unraid 7. |
| l | `share-cfg <share>`, then one harmless `share-set <share> shareComment <text>` | Confirms the share setting names match the gate's safe/sensitive lists for this version. Checks that a gate config edit actually shows up in the WebGUI, and whether it survives a WebGUI page reload. Undo with `cfg-restore`. If edits don't take, config changes go through the WebGUI (owner) instead. |

**Deliverable:** an Initialization report covering the backup reference, gate and `approve.sh` hashes, versions, key list, sshd settings, missing tools, pool names, device and share naming, which switched-off commands were enabled, the result of the config-edit test, and any gaps found. The owner signs it off before Phase 1.

**At the start of every later session:** run `gate-hash` and `authkeys-summary`. Any change → stop and report.

---

## Phase 1 — Health check & inventory (pre-approved, read-only)

All commands are run as `ssh unraid-audit <command>`. Claude announces each batch with a one-line explanation per command.

| Area | Gate commands | What they show |
|---|---|---|
| System | `version` `uname` `uptime` `free` `df` `top` `lscpu` | OS/kernel version, load, memory, space per filesystem (totals only), busiest processes |
| Hardware | `dmi-system` `dmi-memory` `dmi-cpu` `lspci` `lsusb` `lsblk` `nvme-list` `sensors` | Motherboard/BIOS, RAM sticks (ECC?), CPU, PCIe devices and drivers (HBA, NIC, GPU), USB devices, disks (model/serial/connection), temperatures and fans |
| Disk health | `smart-health <dev>` `smart-info <dev>` `smart-all <dev>` `var-ini` `disks-ini` | SMART verdict and attributes (no tests started), Unraid array state, per-disk status and error counts |
| Pools | `zpool-status` `zpool-list` `zfs-list` `btrfs-show` `btrfs-usage <pool>` `btrfs-stats <pool>` | Pool health, capacity, error counters (never reset) |
| Network | `ip-addr` `ip-link` `ip-route` `ethtool <if>` `ethtool-i <if>` `ss` | Interfaces, link speed, driver/firmware, routes, listening ports |
| Config | `ls-config` `ls-shares` `ls-plugins` `ls-templates` `ls-logs` `cfg <file.cfg>` `share-cfg <share>` `go-file` `smb-extra` | File names, and settings with secret values printed as `REDACTED` |
| Docker | `docker-ps` `docker-df` `docker-images` `docker-networks` `docker-inspect <name>` | Containers, ports, space use; inspect shows mounts/network/privileged **without environment variables** |
| VMs | `virsh-list` `virsh-dumpxml <vm>` | VM definitions, with VNC/SPICE passwords removed |
| Logs | `syslog-tail [n]` `syslog-errors` | Recent log and filtered errors/warnings |

**Not available, by design:** listing or reading anything in shares, disks or pools; `du`/`find`; SMB/NFS mounts; raw disk reads; `diagnostics`; `docker logs`/`exec`. SMART self-tests, scrubs and parity checks exist, but in the CHANGE tier (Phase 4), not here.

**Deliverable:** inventory and health summary. Serial numbers, MACs and GUIDs are redacted in anything shared outside the engagement.

---

## Phase 2 — Audit checklist

Grade each item **OK / Warning / Critical** with evidence from Phase 0/1 output only.

- **Security:** root password set (ask the owner); WebGUI not port-forwarded and server not in a DMZ; remote access via WireGuard/Tailscale/Unraid Connect; only necessary ports open (`ss`); SSH key-only, Telnet/FTP off (`sshd-auth`, `cfg ident.cfg`); unexpected root keys (`authkeys-summary`); flash share not exported; shares Private/Secure (`share-cfg`); SMBv1/guest off (`smb-extra`); containers without unnecessary privileged mode, host networking or broad `/mnt/user` mounts (`docker-inspect`); OS, plugins and containers current; unknown plugins.
- **Data protection:** parity present, last check recent with 0 errors (`var-ini`); scheduled parity check is non-correcting; flash backup routine beyond step 0.1; appdata backup scheduled (plugin config / owner); off-site copy (owner); encryption-at-rest if needed.
- **Hardware & disk health:** no disabled/emulated disks or errors; SMART reallocated/pending/uncorrectable/CRC counts; temperatures; power-on hours; pool error counters zero; scrub schedule; cache not near full; BIOS age; ECC; HBA mode; NIC link speed; flash errors in syslog.
- **Shares, cache & mover** (from `share-cfg` and `df`): appdata/system/domains on a pool; primary/secondary storage and mover action fit each share; mover errors in syslog; split level and include/exclude settings sane.
- **Docker:** docker.img not near full; log size limits; consistent appdata mounts; network type; no macvlan instability in logs; unused images.
- **VMs:** vdisks on a pool; CPU pinning; passthrough; autostart.
- **Network:** static IP or DHCP reservation; gateway/DNS; bonding and bridges; link errors.
- **Notifications & monitoring:** alerts for disk, SMART and parity events; persistent syslog.

---

## Phase 3 — Findings report

Each finding gets: ID/title, severity, evidence (gate command and redacted output), risk, recommendation, exact steps with explanations, **tier** (CHANGE / DANGEROUS / owner-only), downtime/impact and rollback. Ordered: data-loss risks → security → stability → performance → tidiness. The owner reviews the report and says which fixes to proceed with. CHANGE-tier fixes then go ahead without further per-action approval; DANGEROUS ones still need the two approvals at the time they run.

---

## Phase 4 — Changes

**Before each day of changes:** a backup less than 24 hours old (repeat step 0.1 and refresh both records). The guard and gate refuse changes without it. Pre-check every time: array normal, no parity check, rebuild or mover run in progress (`var-ini`).

### CHANGE tier — Claude proceeds on its own
For each fix the owner has agreed to in Phase 3:
1. **Explain:** what will run, why, the impact and downtime (e.g. "restarts container X, about 10 s offline"), and the undo.
2. **Run** the gate command. Config edits print the before/after values and the backup name automatically.
3. **Verify** with the read command that found the issue (e.g. `share-cfg`, `docker-ps`). For config edits, also check it in the WebGUI (step 0.6l).
4. **Log** the result. On failure, undo (`cfg-restore <backup>`, `docker-start`, `vm-start` …) and stop.

| CHANGE command | Undo |
|---|---|
| `docker-start` / `docker-stop` / `docker-restart <container>` | the opposite start/stop |
| `vm-start` / `vm-stop <vm>` (graceful) / `vm-autostart <vm> on\|off` | the opposite |
| `smart-test-short` / `smart-test-long <dev>` | none needed (read-only test; adds load) |
| `zpool-scrub <pool>` / `btrfs-scrub <pool>` | none needed (verifies data; adds load) |
| `mover-start` | none needed (moves files per share settings) |
| `parity-check` (non-correcting) / `parity-cancel` *(switched off until 0.6k)* | `parity-cancel` |
| `share-set <share> <safe-key> <value>` | `cfg-restore <backup>` (printed by the command; list with `cfg-backups`) |
| `cfg-restore <share backup>` | `cfg-restore` of the backup it made |

### DANGEROUS tier — explicit owner permission, every time
1. **Claude explains and stops:** exact command, why, what could go wrong, downtime, and how to recover (or that it can't be undone). Claude then asks the owner to approve.
2. **Owner approves on the server:** `bash /boot/config/claude-gate/approve.sh <exact command>` → type `YES`.
3. **Claude runs it; Claude Code shows a permission prompt; the owner answers Yes.** Without both approvals it's refused: the prompt is enforced by Claude Code, the approval file by the gate.
4. **Verify, log, undo on failure**, as above.

| DANGEROUS command | Why it's dangerous | Recovery |
|---|---|---|
| `docker-remove <container>` | deletes the container (stopped containers only) | appdata and template are kept: re-add via **Apps → Previous Apps** |
| `docker-image-prune` | deletes unused (dangling) images | re-pulled automatically when needed |
| `vm-force-stop <vm>` | hard power-off of the VM (like pulling the plug); the VM itself is not deleted | `vm-start`; the guest may need a disk check |
| `share-set <share> <sensitive-key> <value>` | export/security/user-access settings can lock users out | `cfg-restore <backup>` |
| `cfg-set <file.cfg> <key> <value>` | top-level settings (network, SSH, WebGUI ports, Docker, VMs) can cut off access, including Claude's | `cfg-restore <backup>`; worst case restore the flash backup from 0.1 |
| `cfg-restore <non-share backup>` | rewrites a top-level config | `cfg-restore` of the backup it made |
| `parity-check-correct` *(off until 0.6k)* | writes to parity; wrong if a data disk is the problem | none — investigate before running |
| `plugin-install` / `plugin-update` / `plugin-remove` *(off until 0.6k)* | third-party code running as root; updates can break things | reinstall the previous version; flash backup |
| `server-restart` / `server-poweroff` *(off until 0.6k)* | all services down; uses Unraid's clean `powerdown` | power on; check that the array starts |

### Owner-only (never through Claude)
Format, wipe or partition; New Config or disk reassignment; filesystem repair (`xfs_repair`, `btrfs check --repair`); array start/stop; OS upgrades; anything that reads, moves or deletes data inside shares/disks/pools. Claude can write exact step-by-step instructions for these, and the owner performs them.

### Adding a new kind of change
The owner adds one named command to `gate.sh` (with argument checks and a tier) and the same name to `GATE` in `guard.py`, plus an ask rule in `settings.json` if it's DANGEROUS. Then rerun the self-test, reinstall the gate and record the new hash.

---

## Phase 5 — Improvements (proposed, not imposed)
3-2-1 backups (scheduled flash and appdata backups plus off-site); monthly non-correcting parity check; pool scrub and SMART extended test schedules; VPN instead of port forwards; notifications; container hygiene (log limits, pinned tags, unused images); persistent syslog; a written record of the final configuration.

## Phase 6 — Handover
Final report (found / changed / deferred); inventory; change log; maintenance checklist.

**Remove the audit access (owner):**
- delete the audit key's line from `authorized_keys`
- copy `/boot/config/claude-gate/backups/` somewhere safe if you want to keep the config history, then delete `/boot/config/claude-gate/` (gate, `approve.sh`, approvals, backups, marker)
- on the workstation, delete `C:\Users\<you>\.ssh\unraid_audit` and `unraid_audit.pub`, and the `Host unraid-audit` block in `C:\Users\<you>\.ssh\config`
- confirm with `ssh unraid-audit help` → it must fail

## Stop conditions
Stop and report if:
- a disk is disabled or emulated, or read/write errors appear
- a parity check, rebuild or mover run is in progress
- SMART shows rapid degradation
- there are signs of compromise (unknown containers or keys, odd `go` entries)
- the gate hash or key list changed unexpectedly
- any task would require looking inside shares or disks
- a change didn't produce the expected result (undo first, then report)
- an approval appears that the owner didn't create (`approve.sh --list`)

---

## Maintaining the guards
- **Allowlist in two places:** the gate command list and tiers exist in both `server/gate.sh` and `.claude/hooks/guard.py` (`GATE`, `SAFE_SHARE_KEYS`, `SENSITIVE_SHARE_KEYS`). DANGEROUS commands also need an ask rule in `settings.json`. Edit all three, rerun `tests/selftest.sh`, reinstall the gate and record its new hash.
- **Use plain ssh calls:** run `ssh unraid-audit <command>` on its own line, with forward slashes in any path. The guard refuses ssh with pipes, options, backslashes or anything chained.
- **Line endings:** keep `.gitattributes` (`eol=lf`). Without it, Git for Windows checks files out with CRLF, which breaks the bash scripts and changes `gate.sh`'s hash.
- **Permission mode:** Manual (`default`). Bypass and auto modes are disabled so DANGEROUS prompts can't be skipped. Don't run Claude Code in `dontAsk` mode: it denies anything that would prompt, so DANGEROUS actions would simply fail.

---

## Sources
- Unraid docs — Command line interface: https://docs.unraid.net/unraid-os/system-administration/advanced-tools/command-line-interface
- Unraid docs — Capturing diagnostics and logs: https://docs.unraid.net/unraid-os/troubleshooting/diagnostics/capture-diagnostics-and-logs
- Unraid docs — Security good practices: https://docs.unraid.net/unraid-os/manual/security/good-practices
- Unraid docs — Automated flash backup (contents, exclusions, restore): https://docs.unraid.net/unraid-connect/automated-flash-backup
- Unraid forums — Backing up the boot USB (Flash Backup menu path, manual restore, license transfer, disk-reassignment caution): https://forums.unraid.net/topic/95349-how-to-properly-backup-the-boot-usb-and-configuration/page/2/
- Unraid forums — Persisting SSH keys in `/boot/config/ssh/root` (6.9+): https://forums.unraid.net/topic/51160-passwordless-ssh-login/page/3/
- Unraid blog — Security best practices: https://unraid.net/blog/unraid-server-security-best-practices
- Unraid forums — `mover start` usage on Unraid 7.0: https://forums.unraid.net/topic/186908-mover-not-working-on-unraid-700/
- Unraid forums — `mdcmd check` (Unraid 5-era thread; current syntax unconfirmed, hence switched off): https://forums.unraid.net/topic/16233-force-parity-check/
- Claude Code docs — Configure permissions (rule matching, hooks precedence, limits): https://code.claude.com/docs/en/permissions
- Claude Code docs — Sandboxing (not supported on native Windows; Linux/WSL2 option): https://code.claude.com/docs/en/sandboxing
- Claude Code docs — Hooks (`onFailure: "block"`, exec form `args`, Git Bash on Windows): https://code.claude.com/docs/en/hooks
- Claude Code docs — Advanced setup (WinGet install, Git for Windows, Windows options): https://code.claude.com/docs/en/setup
