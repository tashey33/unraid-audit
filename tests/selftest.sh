#!/bin/bash
# Self-test for the audit guard rails. Runs entirely on the workstation: it
# never connects to the server. It only writes inside a temporary folder and
# temporarily swaps .claude/backup-confirmed (restored at the end).
#   1. guard.py   — sample tool calls → allow (0) / prompt (0 + "ask") / block (2)
#   2. gate.sh    — dry-run decisions, tiers, approvals, expiry, freshness
#   3. gate.sh    — real config edit + automatic backup + restore on a temp copy
# Usage (from the project folder):
#   Linux/macOS/WSL/Git Bash:  bash tests/selftest.sh
#   Windows PowerShell:        & "$env:ProgramFiles\Git\bin\bash.exe" tests/selftest.sh
cd "$(dirname "$0")/.." || exit 1
GUARD=".claude/hooks/guard.py"
# Find a real Python 3 (on Windows "python3" is often a Microsoft Store placeholder)
PY=""
for cand in "py -3" python3 python; do
  if $cand -c 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)' >/dev/null 2>&1; then PY="$cand"; break; fi
done
[ -n "$PY" ] || { echo "Python 3.8+ not found (install it: winget install Python.Python.3.12)"; exit 1; }
echo "using Python: $PY"

GATE="server/gate.sh"
APPROVE="server/approve.sh"
export CLAUDE_PROJECT_DIR="$PWD"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
export GATE_APPROVAL_DIR="$TMP/approvals" GATE_BACKUP_DIR="$TMP/backups"
pass=0; fail=0
ok()  { pass=$((pass+1)); }
bad() { fail=$((fail+1)); echo "FAIL $*"; }

# ---------- helpers
hook_rc() {   # tool json -> sets RC and OUT
  OUT="$(printf '{"tool_name":"%s","tool_input":%s,"cwd":"%s"}' "$1" "$2" "$PWD" | $PY "$GUARD" 2>/dev/null)"; RC=$?
}
cmdjson() { $PY -c 'import json,sys;print(json.dumps({"command":sys.argv[1]}))' "$1"; }
bash_ok()  { hook_rc Bash "$(cmdjson "$1")"; { [ $RC = 0 ] && ! grep -q '"ask"' <<<"$OUT"; } && ok || bad "hook allow: $1 (rc=$RC $OUT)"; }
bash_ask() { hook_rc Bash "$(cmdjson "$1")"; { [ $RC = 0 ] && grep -q '"ask"' <<<"$OUT"; } && ok || bad "hook ask: $1 (rc=$RC)"; }
bash_no()  { hook_rc Bash "$(cmdjson "$1")"; [ $RC = 2 ] && ok || bad "hook block: $1 (rc=$RC)"; }
tool_no()  { hook_rc "$1" "$2"; [ $RC = 2 ] && ok || bad "hook block: $1 $2 (rc=$RC)"; }
tool_ok()  { hook_rc "$1" "$2"; [ $RC = 0 ] && ok || bad "hook allow: $1 $2 (rc=$RC)"; }
gate() {      # expect(allow|deny) request [extra env...]
  local expect="$1" req="$2"; shift 2
  local rc got=deny
  env "$@" SSH_ORIGINAL_COMMAND="$req" GATE_DRYRUN=1 bash "$GATE" >/dev/null 2>&1; rc=$?
  [ "$rc" = 0 ] && got=allow
  [ "$got" = "$expect" ] && ok || bad "gate (want $expect got $got): '$req' $*"
}
approve() { echo YES | bash "$APPROVE" "$@" >/dev/null 2>&1; }

MARK=".claude/backup-confirmed"
[ -f "$MARK" ] && mv "$MARK" "$MARK.selftest"
SMARK="$TMP/BACKUP-CONFIRMED"; export GATE_MARKER="$SMARK"

echo "== step 0.1 not done: only 'help' works"
bash_ok "ssh unraid-audit help"
bash_no "ssh unraid-audit uptime"
gate allow help
gate deny uptime

touch "$MARK" "$SMARK"
echo "== guard.py: READ and CHANGE allowed, DANGEROUS prompts"
for c in help "smart-all /dev/sda" "smart-all /dev/nvme0n1" "syslog-tail 500" "cfg ident.cfg" \
         "btrfs-usage cache" "docker-restart plex" "vm-stop Windows11" "vm-autostart Windows11 off" \
         "smart-test-long /dev/sdb" "zpool-scrub tank" "mover-start" "share-set media shareUseCache yes" \
         "cfg-restore shares__media.cfg.20261023-101500"; do bash_ok "ssh unraid-audit $c"; done
for c in "docker-remove plex" docker-image-prune "vm-force-stop Windows11" "cfg-set ident.cfg USE_SSH yes" \
         "share-set media shareSecurity private" "cfg-restore network.cfg.20261023-101500" \
         parity-check-correct "plugin-update unassigned.devices.plg" server-restart server-poweroff; do bash_ask "ssh unraid-audit $c"; done
bash_ok "ls -la"
bash_ok "grep -i error notes.txt | sort | uniq"
tool_ok Read  '{"file_path":"notes/report.md"}'
tool_ok Write '{"file_path":"notes/report.md","content":"x"}'

echo "== guard.py: blocked"
for c in "ssh unraid-audit" "ssh tower help" "ssh -o ProxyCommand=x unraid-audit help" "ssh unraid-audit ls /mnt/user" \
         "ssh unraid-audit smart-all /dev/sda; reboot" "ssh unraid-audit 'smart-all /dev/sda && reboot'" \
         "ssh unraid-audit smart-all /dev/sda | grep x" "ssh unraid-audit btrfs-scrub user" "ssh unraid-audit cfg ../shadow" \
         "ssh unraid-audit share-set media shareMadeUp x" "ssh unraid-audit cfg-set ident.cfg ROOT_PASSWORD x" \
         "ssh unraid-audit share-set media shareUseCache 'yes; rm'" "ssh unraid-audit docker-remove \$(id)" \
         "ssh unraid-audit format /dev/sda" "ssh unraid-audit array-stop" \
         "rm -rf notes" "ls /mnt/user" "cat ~/.ssh/unraid_audit" "find . -delete" "python3 -c print" "bash -c ls" \
         "echo hi > notes/x" "ls && ls" "/bin/ls" "curl https://example.com" "docker ps" "bash server/approve.sh docker-remove plex"; do
  bash_no "$c"; done
tool_no Read  '{"file_path":"/mnt/user/photos/a.jpg"}'
tool_no Read  '{"file_path":"/boot/config/shadow"}'
tool_no Grep  '{"pattern":"x","path":"/mnt/disk1"}'
tool_no Glob  '{"pattern":"/mnt/**/*.jpg"}'
tool_no Write '{"file_path":"/etc/hosts","content":"x"}'
tool_no Edit  '{"file_path":".claude/settings.json","old_string":"a","new_string":"b"}'
tool_no Write '{"file_path":".claude/backup-confirmed","content":"x"}'
tool_no Write '{"file_path":".claude/hooks/guard.py","content":"x"}'
tool_no PowerShell '{"command":"Get-ChildItem"}'
printf 'not json' | $PY "$GUARD" >/dev/null 2>&1; [ $? = 2 ] && ok || bad "hook: bad input should fail closed"

echo "== stale backup (> 24h): READ ok, CHANGE/DANGEROUS refused"
touch -d '2 days ago' "$MARK" "$SMARK"
bash_ok "ssh unraid-audit uptime"
bash_no "ssh unraid-audit docker-restart plex"
bash_no "ssh unraid-audit docker-remove plex"
gate allow uptime
gate deny "docker-restart plex"
touch "$MARK" "$SMARK"

echo "== gate.sh: READ and CHANGE (dry run)"
for r in help version lsblk "smart-all /dev/sda" "cfg ident.cfg" "share-cfg appdata" "docker-inspect plex" \
         "virsh-dumpxml Windows11" "syslog-tail 100" "btrfs-usage cache" tools-check paths-check gate-hash cfg-backups \
         "docker-start plex" "docker-stop plex" "docker-restart plex" "vm-start Windows11" "vm-stop Windows11" \
         "vm-autostart Windows11 on" "smart-test-short /dev/sda" "smart-test-long /dev/nvme0" "zpool-scrub tank" \
         "btrfs-scrub cache" mover-start "share-set media shareUseCache yes" "cfg-restore shares__media.cfg.20261023-101500"; do
  gate allow "$r"; done

echo "== gate.sh: refused"
for r in "" bash "sh -c id" "ls /mnt/user" "cat /boot/config/shadow" "smart-all /dev/sda; reboot" "smart-all /dev/sda && reboot" \
         "smart-all /dev/sda1x" "smart-all /etc/passwd" "cfg ../shadow" "cfg ssh/root/authorized_keys" "share-cfg ../../shadow" \
         "docker-inspect \$(id)" "btrfs-usage user" "btrfs-scrub disk1" "syslog-tail 99999" "version extra" "rm -rf /" \
         "docker rm plex" "smartctl -t long /dev/sda" "help \`id\`" "vm-autostart x maybe" "share-set media shareMadeUp x" \
         "share-set media shareUseCache yes;rm" "cfg-set ident.cfg ROOT_PASSWORD x" "cfg-restore ../../etc/passwd" \
         "format /dev/sda" "array-stop" "plugin-install http://insecure/x.plg"; do gate deny "$r"; done

echo "== gate.sh: switched-off commands stay off until enabled"
gate deny parity-check
gate deny server-restart
gate allow parity-check GATE_ENABLE_ALL=1

echo "== gate.sh: DANGEROUS needs a one-time, unexpired, exact approval"
gate deny "docker-remove plex"
approve docker-remove plex;   gate allow "docker-remove plex"
gate deny "docker-remove plex"                                   # consumed
approve docker-remove plex;   gate deny "docker-remove sonarr"   # different request
gate allow "docker-remove plex"
approve docker-image-prune; touch -d '2 hours ago' "$GATE_APPROVAL_DIR"/*; gate deny docker-image-prune   # expired
approve "docker-remove   plex"; gate allow "docker-remove plex"  # whitespace-normalised
echo no | bash "$APPROVE" vm-force-stop Windows11 >/dev/null 2>&1; gate deny "vm-force-stop Windows11"  # owner said no
approve server-restart;       gate deny server-restart           # approved but switched off
approve server-restart;       gate allow server-restart GATE_ENABLE_ALL=1
approve "share-set media shareSecurity private"; gate allow "share-set media shareSecurity private"
gate deny "share-set media shareSecurity private"
SSH_ORIGINAL_COMMAND="x" bash "$APPROVE" docker-remove plex >/dev/null 2>&1 && bad "approve.sh ran under a forced command" || ok

echo "== gate.sh: critical containers/VMs need approval to start/stop"
gate deny  "docker-restart homeassistant" GATE_CRITICAL_NAMES=" homeassistant "
gate allow "docker-restart plex"          GATE_CRITICAL_NAMES=" homeassistant "
approve docker-restart homeassistant
gate allow "docker-restart homeassistant" GATE_CRITICAL_NAMES=" homeassistant "

echo "== gate.sh: SSH clients can't use the test overrides"
approve "docker-remove plex"
env SSH_CONNECTION="1.2.3.4 1 5.6.7.8 22" GATE_DRYRUN=1 SSH_ORIGINAL_COMMAND="docker-remove plex" bash "$GATE" >/dev/null 2>&1
[ $? = 126 ] && ok || bad "gate: test overrides honoured over SSH"
rm -f "$GATE_APPROVAL_DIR"/*

echo "== gate.sh: real config edit with automatic backup and restore (temp copy)"
CR="$TMP/config"; mkdir -p "$CR/shares"
printf 'shareComment="Media"\nshareUseCache="no"\nshareSecurity="public"\n' > "$CR/shares/media.cfg"
printf 'NAME="Tower"\nUSE_SSH="yes"\n' > "$CR/ident.cfg"
run_real() { env GATE_CONFIG_ROOT="$CR" SSH_ORIGINAL_COMMAND="$1" bash "$GATE" 2>&1; }
run_real "share-set media shareUseCache yes" >/dev/null
grep -qx 'shareUseCache="yes"' "$CR/shares/media.cfg" && ok || bad "share-set did not change the file"
grep -qx 'shareComment="Media"' "$CR/shares/media.cfg" && ok || bad "share-set damaged other lines"
B="$(ls "$GATE_BACKUP_DIR" | head -n1)"
[ -n "$B" ] && grep -qx 'shareUseCache="no"' "$GATE_BACKUP_DIR/$B" && ok || bad "no backup with the old value"
run_real "share-set media shareFloor 50G" >/dev/null 2>&1
grep -c . "$CR/shares/media.cfg" | grep -qx 4 && ok || bad "new key not appended"
sleep 1; run_real "cfg-restore $B" >/dev/null
grep -qx 'shareUseCache="no"' "$CR/shares/media.cfg" && ok || bad "cfg-restore did not restore"
run_real "cfg-set ident.cfg USE_SSH no" >/dev/null 2>&1
grep -qx 'USE_SSH="yes"' "$CR/ident.cfg" && ok || bad "cfg-set changed a file without approval"
approve cfg-set ident.cfg USE_SSH no; run_real "cfg-set ident.cfg USE_SSH no" >/dev/null
grep -qx 'USE_SSH="no"' "$CR/ident.cfg" && ok || bad "approved cfg-set did not apply"

echo "== guard.py: Windows path handling (simulated)"
if $PY tests/guard_windows_sim.py .claude/hooks/guard.py; then ok; else bad "Windows path simulation"; fi

# ---------- restore marker state
rm -f "$MARK"; [ -f "$MARK.selftest" ] && mv "$MARK.selftest" "$MARK"
echo
echo "passed: $pass   failed: $fail"
[ "$fail" = 0 ]
