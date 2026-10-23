#!/usr/bin/env python3
"""
guard.py — PreToolUse hook for the Unraid audit (runs on the workstation).

Claude Code runs this script before every Bash / file tool call and passes the
call as JSON on stdin. Exit code 2 blocks the call (the reason on stderr is
shown to Claude). Exit 0 lets the call continue to the normal permission rules.

Policy (default-deny):
  * Bash may run ONLY:
      - `ssh unraid-audit <gate-command> [args]` — exactly that shape, no ssh
        options, no pipes, nothing chained. The command and arguments must be on
        the same allowlist the server gate enforces (keep GATE in sync with
        server/gate.sh).
          READ       runs once the owner has recorded the step-0.1 backup.
          CHANGE     also needs that backup record to be < MAX_BACKUP_AGE_H old.
          DANGEROUS  same, and this hook asks Claude Code to prompt the owner
                     (settings.json also has ask rules for these). The server
                     gate additionally requires the owner's one-time approval.
      - a short list of local read-only text tools (ls, cat, grep, ...) joined
        by pipes at most, with no redirects, substitutions, ; && || & or
        variables, and never touching /mnt, /dev, /boot or key files.
  * Read / Grep / Glob may not touch /mnt, /dev, /boot/config secrets or ~/.ssh.
  * Edit / Write / NotebookEdit may only write inside the project folder and
    never inside its .claude/ folder (so the guard can't be edited away).
  * PowerShell is blocked.
  * Any error inside this script blocks the call (fail closed).
"""
import json
import os
import re
import shlex
import sys
import time

HOST_ALIAS = "unraid-audit"
MAX_BACKUP_AGE_H = 24
BACKUP_MARKER = ""  # set in main()

DEV = r"/dev/(sd[a-z]{1,3}|nvme[0-9]{1,2}(n[0-9]{1,2})?)"
NAME = r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}"
IFACE = r"[A-Za-z0-9][A-Za-z0-9_.-]{0,14}"
NUM = r"[0-9]{1,4}"
CFG = r"[A-Za-z0-9_-]{1,64}\.cfg"
KEY = r"[A-Za-z0-9_]{1,64}"
VALUE = r"[A-Za-z0-9_.,:-]{1,128}"
BACKUP_NAME = r"[A-Za-z0-9_.-]{1,120}\.cfg\.[0-9]{8}-[0-9]{6}"
PLG = r"[A-Za-z0-9._-]{1,80}\.plg"
PLG_URL = r"https://[A-Za-z0-9.-]+/[A-Za-z0-9._/~:-]+\.plg"

R, C, D, X = "READ", "CHANGE", "DANGEROUS", "BY-ARGUMENT"

# gate command -> (tier, list of allowed argument shapes)
GATE = {
    # ---------------- READ
    "help": (R, [[]]), "version": (R, [[]]), "uname": (R, [[]]), "uptime": (R, [[]]),
    "free": (R, [[]]), "df": (R, [[]]), "top": (R, [[]]), "lscpu": (R, [[]]), "mounts": (R, [[]]),
    "dmi-system": (R, [[]]), "dmi-memory": (R, [[]]), "dmi-cpu": (R, [[]]), "lspci": (R, [[]]),
    "lsusb": (R, [[]]), "lsblk": (R, [[]]), "nvme-list": (R, [[]]), "sensors": (R, [[]]),
    "smart-info": (R, [[DEV]]), "smart-health": (R, [[DEV]]), "smart-all": (R, [[DEV]]),
    "var-ini": (R, [[]]), "disks-ini": (R, [[]]),
    "zpool-status": (R, [[]]), "zpool-list": (R, [[]]), "zfs-list": (R, [[]]), "btrfs-show": (R, [[]]),
    "btrfs-usage": (R, [[NAME]]), "btrfs-stats": (R, [[NAME]]),
    "ip-addr": (R, [[]]), "ip-link": (R, [[]]), "ip-route": (R, [[]]),
    "ethtool": (R, [[IFACE]]), "ethtool-i": (R, [[IFACE]]), "ss": (R, [[]]),
    "ls-config": (R, [[]]), "ls-shares": (R, [[]]), "ls-plugins": (R, [[]]), "ls-templates": (R, [[]]),
    "ls-logs": (R, [[]]), "cfg": (R, [[CFG]]), "share-cfg": (R, [[NAME]]), "go-file": (R, [[]]),
    "smb-extra": (R, [[]]), "cfg-backups": (R, [[]]),
    "docker-ps": (R, [[]]), "docker-df": (R, [[]]), "docker-images": (R, [[]]),
    "docker-networks": (R, [[]]), "docker-inspect": (R, [[NAME]]),
    "virsh-list": (R, [[]]), "virsh-dumpxml": (R, [[NAME]]),
    "syslog-tail": (R, [[], [NUM]]), "syslog-errors": (R, [[]]),
    "tools-check": (R, [[]]), "paths-check": (R, [[]]), "authkeys-summary": (R, [[]]),
    "sshd-auth": (R, [[]]), "ssh-version": (R, [[]]), "gate-hash": (R, [[]]),
    # ---------------- CHANGE
    "docker-start": (C, [[NAME]]), "docker-stop": (C, [[NAME]]), "docker-restart": (C, [[NAME]]),
    "vm-start": (C, [[NAME]]), "vm-stop": (C, [[NAME]]), "vm-autostart": (C, [[NAME, "on|off"]]),
    "smart-test-short": (C, [[DEV]]), "smart-test-long": (C, [[DEV]]),
    "zpool-scrub": (C, [[NAME]]), "btrfs-scrub": (C, [[NAME]]), "mover-start": (C, [[]]),
    "parity-check": (C, [[]]), "parity-cancel": (C, [[]]),
    # ---------------- tier decided by the arguments
    "share-set": (X, [[NAME, KEY, VALUE]]),
    "cfg-restore": (X, [[BACKUP_NAME]]),
    # ---------------- DANGEROUS
    "docker-remove": (D, [[NAME]]), "docker-image-prune": (D, [[]]), "vm-force-stop": (D, [[NAME]]),
    "cfg-set": (D, [[CFG, KEY, VALUE]]), "parity-check-correct": (D, [[]]),
    "plugin-install": (D, [[PLG_URL]]), "plugin-update": (D, [[PLG]]), "plugin-remove": (D, [[PLG]]),
    "server-restart": (D, [[]]), "server-poweroff": (D, [[]]),
}
SAFE_SHARE_KEYS = {"shareComment", "shareAllocator", "shareFloor", "shareSplitLevel", "shareInclude",
                   "shareExclude", "shareUseCache", "shareCachePool", "shareCachePool2"}
SENSITIVE_SHARE_KEYS = {"shareExport", "shareSecurity", "shareExportNFS", "shareSecurityNFS",
                        "shareHostListNFS", "shareReadList", "shareWriteList", "shareCaseSensitive", "shareFruit"}
SECRET_KEY = re.compile(r"(pass|secret|token|key|guid|regto|email|psk)", re.I)
POOL_FORBIDDEN = {"user", "user0", "disks", "remotes", "addons", "rootshare"}

LOCAL_TOOLS = {"ls", "cat", "head", "tail", "grep", "egrep", "wc", "sort", "uniq",
               "cut", "diff", "echo", "pwd", "date", "stat", "file", "sha256sum"}

HOME = os.path.expanduser("~")
PROTECTED_READ = [
    "/mnt", "/dev", "/boot/config/shadow", "/boot/config/passwd",
    "/boot/config/smbpasswd", "/boot/config/ssh", "/boot/config/ssl",
    "/boot/config/wireguard", "/boot/config/claude-gate", "/etc/shadow", "/root/.ssh",
    os.path.join(HOME, ".ssh"),
]
SECRET_WORDS = re.compile(r"(id_rsa|id_ed25519|id_ecdsa|unraid_audit|shadow|smbpasswd|authorized_keys|\.ssh|approve\.sh)", re.I)


def block(reason: str) -> None:
    print(f"BLOCKED by audit guard: {reason}", file=sys.stderr)
    sys.exit(2)


def ask(reason: str) -> None:
    """Ask Claude Code to show the owner a permission prompt for this call."""
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "ask",
        "permissionDecisionReason": reason}}))
    sys.exit(0)


def norm(path: str, cwd: str) -> str:
    path = os.path.expanduser(path)
    if not os.path.isabs(path):
        path = os.path.join(cwd, path)
    return os.path.realpath(path)


def under(path: str, root: str) -> bool:
    root = root.rstrip("/") or "/"
    return path == root or path.startswith(root + "/")


def check_read_path(path: str, cwd: str) -> None:
    p = norm(path, cwd)
    for root in PROTECTED_READ:
        if under(p, os.path.realpath(root) if os.path.exists(root) else root):
            block(f"reading {p} is off-limits (personal data / devices / secrets)")


def full(rx: str, s: str) -> bool:
    return re.fullmatch(rx, s) is not None


def gate_tier(args: list) -> str:
    """Validate a gate request; return its tier or block."""
    if not args:
        block("interactive ssh sessions are not allowed; send a gate command (e.g. 'help')")
    cmd, rest = args[0], args[1:]
    entry = GATE.get(cmd)
    if entry is None:
        block(f"'{cmd}' is not a gate command (run: ssh {HOST_ALIAS} help)")
    tier, shapes = entry
    if not any(len(s) == len(rest) and all(full(rx, a) for rx, a in zip(s, rest)) for s in shapes):
        block(f"arguments for '{cmd}' don't match the allowed shape")
    if cmd in ("btrfs-usage", "btrfs-stats", "btrfs-scrub") and (rest[0] in POOL_FORBIDDEN or full(r"disk[0-9]+", rest[0])):
        block(f"'{rest[0]}' is not a pool")
    if cmd in ("share-set", "cfg-set") and SECRET_KEY.search(rest[-2]):
        block("secret-type settings (passwords/keys/tokens) can't be changed through the gate")
    if cmd == "share-set":
        if rest[1] in SAFE_SHARE_KEYS:
            return C
        if rest[1] in SENSITIVE_SHARE_KEYS:
            return D
        block(f"'{rest[1]}' is not a recognised share setting")
    if cmd == "cfg-restore":
        return C if rest[0].startswith("shares__") else D
    return tier


def backup_age_hours() -> float:
    if not os.path.isfile(BACKUP_MARKER):
        return float("inf")
    return (time.time() - os.path.getmtime(BACKUP_MARKER)) / 3600


def check_bash(command: str, cwd: str) -> None:
    if under(norm(cwd, "/"), "/mnt") or under(norm(cwd, "/"), "/boot"):
        block("commands may not run from inside /mnt or /boot")
    if "\n" in command or "\r" in command:
        block("multi-line commands are not allowed")
    for bad in ("`", "$(", "${", "$", "<(", ">(", "\\"):
        if bad in command:
            block(f"'{bad}' (substitution/variables/escapes) is not allowed")

    lex = shlex.shlex(command, posix=True, punctuation_chars=True)
    lex.whitespace_split = True
    tokens = list(lex)
    if not tokens:
        block("empty command")

    segments, cur = [], []
    for t in tokens:
        if t == "|":
            if not cur:
                block("malformed pipeline")
            segments.append(cur)
            cur = []
        elif t and all(ch in "();<>|&" for ch in t):
            block(f"operator '{t}' is not allowed (only simple pipes between local read-only tools)")
        else:
            cur.append(t)
    if not cur:
        block("malformed pipeline")
    segments.append(cur)

    first = segments[0]
    if first[0] == "ssh":
        if len(segments) != 1:
            block("ssh must run on its own (no pipes) — the sandbox only lets a bare 'ssh unraid-audit ...' out")
        if len(first) < 2 or first[1] != HOST_ALIAS:
            block(f"ssh is only allowed as 'ssh {HOST_ALIAS} <gate-command>' (no options, no other hosts)")
        req = first[2:]
        tier = gate_tier(req)
        if req == ["help"]:
            return
        age = backup_age_hours()
        if age == float("inf"):
            block("initialization step 0.1 not done: the owner must export a flash backup to another "
                  "machine and record it in .claude/backup-confirmed before any server command runs")
        if tier in (C, D) and age > MAX_BACKUP_AGE_H:
            block(f"changes need a flash backup from the last {MAX_BACKUP_AGE_H}h: the owner repeats "
                  "step 0.1 and updates .claude/backup-confirmed (and the server marker)")
        if tier == D:
            ask(f"DANGEROUS: '{' '.join(req)}'. Approve only if you asked for this exact action. "
                f"The server also needs your one-time approval: bash /boot/config/claude-gate/approve.sh {' '.join(req)}")
        return

    for seg in segments:
        prog = os.path.basename(seg[0])
        if seg[0] != prog:
            block("call local tools by name, not by path")
        if prog not in LOCAL_TOOLS:
            block(f"'{prog}' is not on the local read-only list ({', '.join(sorted(LOCAL_TOOLS))}); "
                  f"server commands go through 'ssh {HOST_ALIAS} <gate-command>'")
        for arg in seg[1:]:
            if arg.startswith("-") and "=" in arg:
                val = arg.split("=", 1)[1]
                if val.startswith(("/", "~", ".")):
                    check_read_path(val, cwd)
            if SECRET_WORDS.search(arg):
                block(f"argument '{arg}' refers to keys/secrets")
            if arg.startswith(("/", "~", ".")) or "/" in arg:
                check_read_path(arg, cwd)


def check_write_path(path: str, cwd: str, project: str) -> None:
    p = norm(path, cwd)
    proj = os.path.realpath(project)
    if not under(p, proj):
        block(f"writes are only allowed inside the project folder ({proj})")
    if under(p, os.path.join(proj, ".claude")):
        block("the .claude folder (settings, this guard, backup record) can't be changed by Claude")


def main() -> None:
    global BACKUP_MARKER
    data = json.load(sys.stdin)
    tool = data.get("tool_name", "")
    ti = data.get("tool_input") or {}
    cwd = data.get("cwd") or os.getcwd()
    project = os.environ.get("CLAUDE_PROJECT_DIR") or cwd
    # Created by the OWNER after step 0.1. Claude can't create or touch it:
    # writes into .claude/ are blocked below and Bash has no write-capable tools.
    BACKUP_MARKER = os.path.join(os.path.realpath(project), ".claude", "backup-confirmed")

    if tool == "Bash":
        check_bash(str(ti.get("command", "")), cwd)
    elif tool == "PowerShell":
        block("PowerShell is not used in this audit")
    elif tool in ("Read", "NotebookRead"):
        check_read_path(str(ti.get("file_path") or ti.get("notebook_path") or ""), cwd)
    elif tool in ("Grep", "Glob"):
        check_read_path(str(ti.get("path") or cwd), cwd)
        for key in ("pattern", "glob"):
            val = str(ti.get(key) or "")
            if tool == "Glob" or key == "glob":
                if val.startswith(("/", "~")) or ".." in val:
                    check_read_path(val.split("*", 1)[0] or "/", cwd)
    elif tool in ("Edit", "Write", "MultiEdit", "NotebookEdit"):
        check_write_path(str(ti.get("file_path") or ti.get("notebook_path") or ""), cwd, project)
    sys.exit(0)


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:  # fail closed
        print(f"BLOCKED by audit guard: guard error ({type(exc).__name__}: {exc})", file=sys.stderr)
        sys.exit(2)
