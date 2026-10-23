#!/bin/bash
# =============================================================================
# claude-gate — command gate for the Claude audit SSH key (Unraid)
#
# Installed by the OWNER, not by Claude:
#   /boot/config/claude-gate/gate.sh      (this file)
#   /boot/config/claude-gate/approve.sh   (owner-only approval helper)
# and bound to ONE dedicated key in /boot/config/ssh/root/authorized_keys:
#   restrict,from="<workstation-IP>",command="/bin/bash /boot/config/claude-gate/gate.sh" ssh-ed25519 AAAA... claude-audit
#
# sshd runs this script instead of whatever the client asked for; the request
# arrives in $SSH_ORIGINAL_COMMAND. It must be ONE named command below with
# validated arguments. Shells, pipes, ;, &&, $(), quotes and unknown commands
# are refused. Commands run with fixed argument lists (no eval / bash -c).
#
# THREE TIERS
#   READ       read-only health/inventory/config.
#   CHANGE     reversible changes (start/stop containers & VMs, SMART tests,
#              scrubs, mover, safe share settings). Config edits are
#              auto-backed-up.
#   DANGEROUS  destructive / hard-to-undo / lock-out risk. Needs a one-time
#              approval the owner creates for that EXACT request
#              with approve.sh from their own root session. Approvals expire
#              after APPROVAL_TTL_MIN and are consumed on use.
#   NEVER      not implemented at all: format/wipe/partition, New Config, disk
#              assignment, filesystem repair, array start/stop, OS upgrade,
#              deleting or reading anything inside shares/disks/pools.
#
# Every request is logged to syslog with tag "claude-gate"
# (ALLOW / DENY / APPROVAL-USED). Claude has no command that can write to this
# file, approve.sh or the approvals folder.
# =============================================================================
set -u
export PATH=/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin
export LC_ALL=C

# ---------------------------------------------------------------- settings
APPROVAL_TTL_MIN=30        # one-time approvals expire after this
# Commands whose syntax could not be confirmed from Unraid's docs ship OFF.
# Confirm the syntax on your Unraid version (plan step 0.6k), then set to 1.
ENABLE_PARITY=0            # mdcmd check NOCORRECT / CORRECT, mdcmd nocheck
ENABLE_PLUGINS=0           # plugin install / update / remove
ENABLE_POWER=0             # powerdown -r (restart) / powerdown (power off)

# Containers / VMs the owner calls critical: starting, stopping, restarting or
# changing autostart for these is DANGEROUS (needs approval) instead of CHANGE.
# Space-separated, e.g. CRITICAL_NAMES=" homeassistant pihole Windows11 "
CRITICAL_NAMES=" homeassistant homebridge omada-controller-1 "

# Share settings Claude may change without per-action approval (CHANGE tier)
SAFE_SHARE_KEYS=" shareComment shareAllocator shareFloor shareSplitLevel shareInclude shareExclude shareUseCache shareCachePool shareCachePool2 "
# Share settings that can lock users out (DANGEROUS tier)
SENSITIVE_SHARE_KEYS=" shareExport shareSecurity shareExportNFS shareSecurityNFS shareHostListNFS shareReadList shareWriteList shareCaseSensitive shareFruit "

TAG="claude-gate"
REQ="${SSH_ORIGINAL_COMMAND:-}"
GATE_DIR="/boot/config/claude-gate"
GATE_PATH="$GATE_DIR/gate.sh"
APPROVAL_DIR="$GATE_DIR/approvals"
BACKUP_DIR="$GATE_DIR/backups"
CONFIG_ROOT="/boot/config"
DRYRUN=0
# Test overrides are honoured only when NOT reached over SSH, so a client can't
# set them (even if sshd's AcceptEnv were to allow it).
if [ -z "${SSH_CONNECTION:-}" ] && [ -z "${SSH_CLIENT:-}" ]; then
  DRYRUN="${GATE_DRYRUN:-0}"
  APPROVAL_DIR="${GATE_APPROVAL_DIR:-$APPROVAL_DIR}"
  BACKUP_DIR="${GATE_BACKUP_DIR:-$BACKUP_DIR}"
  CONFIG_ROOT="${GATE_CONFIG_ROOT:-$CONFIG_ROOT}"
  if [ "${GATE_ENABLE_ALL:-0}" = "1" ]; then ENABLE_PARITY=1; ENABLE_PLUGINS=1; ENABLE_POWER=1; fi
  CRITICAL_NAMES="${GATE_CRITICAL_NAMES:-$CRITICAL_NAMES}"
fi

log()  { logger -t "$TAG" -- "$*" 2>/dev/null || true; }
deny() { log "DENY: [$REQ] $1"; echo "claude-gate: DENIED - $1" >&2; exit 126; }
allow_log() { log "ALLOW${TIER:+ ($TIER)}: [$REQ]"; }

run() {   # fixed argument list, exec = no shell interpretation
  allow_log
  if [ "$DRYRUN" = "1" ]; then printf 'DRYRUN:'; printf ' %q' "$@"; echo; exit 0; fi
  exec "$@"
}

REDACT_SED='s/^([[:space:]]*[A-Za-z0-9_.-]*(pass|secret|token|key|guid|regto|email|psk)[A-Za-z0-9_.-]*[[:space:]]*=[[:space:]]*).*/\1"REDACTED"/I'
SECRET_KEY_RX='(pass|secret|token|key|guid|regto|email|psk)'

print_redacted() {
  if [ "$DRYRUN" = "1" ]; then allow_log; echo "DRYRUN: sed -E <redact> $1"; exit 0; fi
  [ -L "$1" ] && deny "symlinks not allowed: $1"
  [ -f "$1" ] || deny "file not found: $1"
  allow_log
  exec sed -E "$REDACT_SED" -- "$1"
}

# ---------------------------------------------------------------- validation
[ -n "$REQ" ] || deny "interactive shells are not allowed (send a gate command, e.g. 'help')"
[ "${#REQ}" -le 300 ] || deny "request too long"
case "$REQ" in
  *[!A-Za-z0-9\ ._:/=,~-]*) deny "disallowed characters (only letters, digits, space and . _ : / = , ~ - are accepted)";;
esac
read -r -a A <<< "$REQ"
CMD="${A[0]}"
N="${#A[@]}"
NREQ="${A[*]}"          # normalised request (single spaces) — what approvals are bound to
TIER=""

argc()  { [ "$N" -eq "$1" ] || deny "'$CMD' takes $(( $1 - 1 )) argument(s)"; }
argc_range() { { [ "$N" -ge "$1" ] && [ "$N" -le "$2" ]; } || deny "wrong number of arguments for '$CMD'"; }
v_dev() {
  [[ "$1" =~ ^/dev/(sd[a-z]{1,3}|nvme[0-9]{1,2}(n[0-9]{1,2})?)$ ]] || deny "device must look like /dev/sda or /dev/nvme0n1"
  [ "$DRYRUN" = "1" ] || [ -b "$1" ] || [ -c "$1" ] || deny "no such device: $1"
}
v_name()  { [[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$ ]] || deny "name may only contain letters, digits, _ . -"; }
v_iface() { [[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,14}$ ]] || deny "bad interface name"; }
v_num()   { [[ "$1" =~ ^[0-9]{1,4}$ ]] && [ "$1" -ge 1 ] && [ "$1" -le 2000 ] || deny "number must be 1-2000"; }
v_value() { [[ "$1" =~ ^[A-Za-z0-9_.,:-]{1,128}$ ]] || deny "value may only contain letters, digits and _ . , : -"; }
v_key()   { [[ "$1" =~ ^[A-Za-z0-9_]{1,64}$ ]] || deny "bad setting name"
            echo "$1" | grep -qiE "$SECRET_KEY_RX" && deny "secret-type settings (passwords/keys/tokens) can't be changed through the gate"; return 0; }
v_btrfs_pool() {
  v_name "$1"
  case "$1" in user|user0|disks|remotes|addons|rootshare|disk[0-9]*) deny "not a pool: $1";; esac
  [ "$DRYRUN" = "1" ] && return 0
  [ "$(findmnt -n -o FSTYPE --mountpoint "/mnt/$1" 2>/dev/null)" = "btrfs" ] || deny "/mnt/$1 is not a mounted btrfs pool"
}
v_zpool() {
  v_name "$1"
  [ "$DRYRUN" = "1" ] && return 0
  zpool list -H -o name 2>/dev/null | grep -qx -- "$1" || deny "no ZFS pool named $1"
}
enabled() { [ "$1" = "1" ] || deny "'$CMD' is switched off until its syntax is confirmed on this server (see gate.sh settings)"; }

# ---- tiers / approvals
# (The plan tells the owner to take a flash backup before changes; the gate
#  does not check for it.)
tier_change()    { TIER="CHANGE"; }
tier_for_name()  { if [[ "$CRITICAL_NAMES" == *" $1 "* ]]; then tier_dangerous; else tier_change; fi; }
tier_dangerous() {
  TIER="DANGEROUS"
  local h f age
  h="$(printf '%s' "$NREQ" | sha256sum | cut -d' ' -f1)"
  f="$APPROVAL_DIR/$h"
  [ -f "$f" ] || deny "DANGEROUS action needs the owner's one-time approval. Owner runs, from their own root session: bash $GATE_DIR/approve.sh $NREQ"
  age=$(( $(date +%s) - $(stat -c %Y "$f") ))
  if [ "$age" -gt $(( APPROVAL_TTL_MIN * 60 )) ]; then rm -f -- "$f"; deny "approval expired (older than ${APPROVAL_TTL_MIN} min) — owner must approve again"; fi
  rm -f -- "$f" || deny "could not consume approval"
  log "APPROVAL-USED: [$NREQ]"
}

# ---- config editing with automatic backup
backup_id() { local rel="${1#$CONFIG_ROOT/}"; echo "${rel//\//__}"; }   # shares/x.cfg -> shares__x.cfg
backup_file() {   # $1 = file; prints backup name
  mkdir -p -- "$BACKUP_DIR" || deny "can't create $BACKUP_DIR"
  local name; name="$(backup_id "$1").$(date +%Y%m%d-%H%M%S)"
  while [ -e "$BACKUP_DIR/$name" ]; do sleep 1; name="$(backup_id "$1").$(date +%Y%m%d-%H%M%S)"; done   # never overwrite a backup
  cp -p -- "$1" "$BACKUP_DIR/$name" || deny "backup of $1 failed — nothing changed"
  echo "$name"
}
set_kv() {   # $1 file  $2 key  $3 value
  local f="$1" k="$2" v="$3" b old
  if [ "$DRYRUN" = "1" ]; then allow_log; echo "DRYRUN: set $k=\"$v\" in $f"; exit 0; fi
  [ -L "$f" ] && deny "symlinks not allowed: $f"
  [ -f "$f" ] || deny "file not found: $f"
  old="$(grep -m1 -E "^$k=" -- "$f" || echo "$k=(not set)")"
  allow_log
  b="$(backup_file "$f")"
  awk -v k="$k" -v v="$v" 'BEGIN{d=0} index($0, k"=")==1 {print k"=\""v"\""; d=1; next} {print} END{if(!d) print k"=\""v"\""}' "$f" > "$f.claude-tmp" \
    && mv -f -- "$f.claude-tmp" "$f" || { rm -f -- "$f.claude-tmp"; deny "write failed — $f unchanged (backup: $b)"; }
  log "CHANGED: $f $k (was: $old) backup=$b"
  echo "changed: $f"
  echo "  before: $old"
  echo "  after:  $k=\"$v\""
  echo "  backup: $b   (undo: cfg-restore $b)"
  echo "note: Unraid may only apply this after the matching WebGUI page/service reloads it — verify, and use the WebGUI if it doesn't take."
  exit 0
}

# ------------------------------------------------------------------ commands
case "$CMD" in
  help) argc 1; allow_log; cat <<EOF
claude-gate commands. Arguments in <>.
READ
 system:   version  uname  uptime  free  df  top  lscpu  mounts
 hardware: dmi-system  dmi-memory  dmi-cpu  lspci  lsusb  lsblk  nvme-list  sensors
 disks:    smart-info <dev>  smart-health <dev>  smart-all <dev>  var-ini  disks-ini
 pools:    zpool-status  zpool-list  zfs-list  btrfs-show  btrfs-usage <pool>  btrfs-stats <pool>
 network:  ip-addr  ip-link  ip-route  ethtool <iface>  ethtool-i <iface>  ss
 config:   ls-config  ls-shares  ls-plugins  ls-templates  ls-logs  cfg <file.cfg>  share-cfg <share>
           go-file  smb-extra  cfg-backups
 docker:   docker-ps  docker-df  docker-images  docker-networks  docker-inspect <container>
 vms:      virsh-list  virsh-dumpxml <vm>
 logs:     syslog-tail [lines]  syslog-errors
 init:     tools-check  paths-check  authkeys-summary  sshd-auth  ssh-version  gate-hash
CHANGE (reversible; runs without per-action approval)
 docker-start|docker-stop|docker-restart <container>
 vm-start <vm>   vm-stop <vm> (graceful)   vm-autostart <vm> on|off
 smart-test-short <dev>   smart-test-long <dev>
 zpool-scrub <zfs-pool>   btrfs-scrub <btrfs-pool>   mover-start
 parity-check (non-correcting)   parity-cancel                      [off: ENABLE_PARITY=$ENABLE_PARITY]
 share-set <share> <safe-key> <value>   cfg-restore <backup> (share files)
DANGEROUS (needs owner approval via approve.sh, one use, ${APPROVAL_TTL_MIN} min)
 docker-remove <container>   docker-image-prune   vm-force-stop <vm>
 share-set <share> <sensitive-key> <value>   cfg-set <file.cfg> <key> <value>   cfg-restore <backup> (other files)
 parity-check-correct                                               [off: ENABLE_PARITY=$ENABLE_PARITY]
 plugin-install <https-url.plg>  plugin-update <name.plg>  plugin-remove <name.plg>   [off: ENABLE_PLUGINS=$ENABLE_PLUGINS]
 server-restart   server-poweroff                                   [off: ENABLE_POWER=$ENABLE_POWER]
NEVER via the gate: format/wipe/partition, New Config, disk assignment, filesystem repair,
 array start/stop, OS upgrade, reading or deleting anything inside shares/disks/pools.
EOF
    exit 0;;

  # =========================== READ ===========================
  version)  argc 1; run cat /etc/unraid-version;;
  uname)    argc 1; run uname -a;;
  uptime)   argc 1; run uptime;;
  free)     argc 1; run free -h;;
  df)       argc 1; run df -hT;;
  top)      argc 1; run top -b -n 1;;
  lscpu)    argc 1; run lscpu;;
  mounts)   argc 1; run findmnt -rn -o TARGET,SOURCE,FSTYPE;;
  dmi-system) argc 1; run dmidecode -t system -t baseboard -t bios -t chassis;;
  dmi-memory) argc 1; run dmidecode -t memory;;
  dmi-cpu)    argc 1; run dmidecode -t processor;;
  lspci)      argc 1; run lspci -nnk;;
  lsusb)      argc 1; run lsusb;;
  lsblk)      argc 1; run lsblk -o NAME,SIZE,TYPE,FSTYPE,LABEL,MOUNTPOINT,MODEL,SERIAL,TRAN,ROTA;;
  nvme-list)  argc 1; run nvme list;;
  sensors)    argc 1; run sensors;;
  smart-info)   argc 2; v_dev "${A[1]}"; run smartctl -i "${A[1]}";;
  smart-health) argc 2; v_dev "${A[1]}"; run smartctl -H "${A[1]}";;
  smart-all)    argc 2; v_dev "${A[1]}"; run smartctl -a "${A[1]}";;
  var-ini)      argc 1; print_redacted /var/local/emhttp/var.ini;;
  disks-ini)    argc 1; print_redacted /var/local/emhttp/disks.ini;;
  zpool-status) argc 1; run zpool status -v;;
  zpool-list)   argc 1; run zpool list -v;;
  zfs-list)     argc 1; run zfs list -o name,used,avail,refer,mountpoint;;
  btrfs-show)   argc 1; run btrfs filesystem show;;
  btrfs-usage)  argc 2; v_btrfs_pool "${A[1]}"; run btrfs filesystem usage -T "/mnt/${A[1]}";;
  btrfs-stats)  argc 2; v_btrfs_pool "${A[1]}"; run btrfs device stats "/mnt/${A[1]}";;
  ip-addr)   argc 1; run ip -br addr;;
  ip-link)   argc 1; run ip -br link;;
  ip-route)  argc 1; run ip route;;
  ethtool)   argc 2; v_iface "${A[1]}"; run ethtool "${A[1]}";;
  ethtool-i) argc 2; v_iface "${A[1]}"; run ethtool -i "${A[1]}";;
  ss)        argc 1; run ss -tulpn;;
  ls-config)    argc 1; run ls -la "$CONFIG_ROOT";;
  ls-shares)    argc 1; run ls -la "$CONFIG_ROOT/shares";;
  ls-plugins)   argc 1; run ls -la "$CONFIG_ROOT/plugins";;
  ls-templates) argc 1; run ls -la "$CONFIG_ROOT/plugins/dockerMan/templates-user";;
  ls-logs)      argc 1; run ls -la /boot/logs;;
  cfg)
    argc 2; [[ "${A[1]}" =~ ^[A-Za-z0-9_-]{1,64}\.cfg$ ]] || deny "cfg takes a top-level file name like ident.cfg"
    print_redacted "$CONFIG_ROOT/${A[1]}";;
  share-cfg) argc 2; v_name "${A[1]}"; print_redacted "$CONFIG_ROOT/shares/${A[1]}.cfg";;
  go-file)   argc 1; print_redacted "$CONFIG_ROOT/go";;
  smb-extra) argc 1; print_redacted "$CONFIG_ROOT/smb-extra.conf";;
  cfg-backups) argc 1; allow_log; [ -d "$BACKUP_DIR" ] && ls -la "$BACKUP_DIR" || echo "no config backups yet"; exit 0;;
  docker-ps)       argc 1; run docker ps -a --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}';;
  docker-df)       argc 1; run docker system df;;
  docker-images)   argc 1; run docker images;;
  docker-networks) argc 1; run docker network ls;;
  docker-inspect)
    argc 2; v_name "${A[1]}"
    run docker inspect --format '{{json .Name}} {{json .Config.Image}} {{json .HostConfig}} {{json .Mounts}} {{json .NetworkSettings.Networks}}' -- "${A[1]}";;
  virsh-list) argc 1; run virsh list --all;;
  virsh-dumpxml)
    argc 2; v_name "${A[1]}"; allow_log
    if [ "$DRYRUN" = "1" ]; then echo "DRYRUN: virsh dumpxml ${A[1]} | sed <redact passwd>"; exit 0; fi
    virsh dumpxml -- "${A[1]}" | sed -E "s/passwd='[^']*'/passwd='REDACTED'/g; s/passwd=\"[^\"]*\"/passwd=\"REDACTED\"/g"
    exit "${PIPESTATUS[0]}";;
  syslog-tail)
    argc_range 1 2; L=200; [ "$N" -eq 2 ] && { v_num "${A[1]}"; L="${A[1]}"; }
    run tail -n "$L" /var/log/syslog;;
  syslog-errors)
    argc 1; allow_log
    if [ "$DRYRUN" = "1" ]; then echo "DRYRUN: grep -iE <pattern> /var/log/syslog | tail -n 200"; exit 0; fi
    grep -iE 'error|fail|warn|crc|i/o|call trace|segfault' /var/log/syslog | tail -n 200; exit 0;;
  tools-check)
    argc 1; allow_log
    for t in smartctl nvme sensors dmidecode lspci lsusb lsblk findmnt zpool zfs btrfs docker virsh ethtool ss ip logger sshd mover mdcmd plugin powerdown; do
      if command -v "$t" >/dev/null 2>&1; then echo "present  $t ($(command -v "$t"))"; else echo "MISSING  $t"; fi
    done; exit 0;;
  paths-check)
    argc 1; allow_log
    for p in /etc/unraid-version /var/local/emhttp/var.ini /var/local/emhttp/disks.ini \
             /boot/config/ident.cfg /boot/config/share.cfg /boot/config/disk.cfg /boot/config/docker.cfg \
             /boot/config/domain.cfg /boot/config/network.cfg /boot/config/go /boot/config/smb-extra.conf \
             /boot/config/shares /boot/config/plugins /boot/config/plugins/dockerMan/templates-user /boot/logs \
             /boot/config/ssh/root /root/.ssh /var/log/syslog \
             /boot/config/shadow /boot/config/passwd /boot/config/smbpasswd /boot/config/wireguard /boot/config/ssl \
             "$GATE_DIR/approve.sh" "$APPROVAL_DIR" "$BACKUP_DIR"; do
      if [ -e "$p" ]; then
        if [ -L "$p" ]; then echo "present (symlink -> $(readlink "$p"))  $p"; else echo "present  $p"; fi
      else echo "missing  $p"; fi
    done; exit 0;;
  authkeys-summary)
    argc 1; allow_log
    F=/root/.ssh/authorized_keys; [ -f "$F" ] || { echo "no $F"; exit 0; }
    awk '!/^[[:space:]]*(#|$)/ {
           t="?"; c=""; o="no-options"
           if ($1 ~ /^(ssh-|ecdsa-|sk-)/) { t=$1; c=$3 }
           else { o="HAS-OPTIONS"; for (i=1;i<=NF;i++) if ($i ~ /^(ssh-|ecdsa-|sk-)/) { t=$i; c=$(i+2); break } }
           g = ($0 ~ /claude-gate/) ? " [bound to claude-gate]" : ""
           print "line " NR ": " t "  " o "  comment=" c g }' "$F"; exit 0;;
  sshd-auth)
    argc 1; allow_log
    sshd -T 2>/dev/null | grep -Ei '^(port|listenaddress|permitrootlogin|passwordauthentication|kbdinteractiveauthentication|pubkeyauthentication|allowtcpforwarding|x11forwarding|permitopen|authorizedkeysfile) '
    exit 0;;
  ssh-version) argc 1; allow_log; ssh -V 2>&1; exit 0;;
  gate-hash)   argc 1; run sha256sum "$GATE_PATH" "$GATE_DIR/approve.sh";;

  # =========================== CHANGE ===========================
  docker-start|docker-stop|docker-restart)
    argc 2; v_name "${A[1]}"; tier_for_name "${A[1]}"; run docker "${CMD#docker-}" -- "${A[1]}";;
  vm-start) argc 2; v_name "${A[1]}"; tier_for_name "${A[1]}"; run virsh start -- "${A[1]}";;
  vm-stop)  argc 2; v_name "${A[1]}"; tier_for_name "${A[1]}"; run virsh shutdown -- "${A[1]}";;
  vm-autostart)
    argc 3; v_name "${A[1]}"; tier_for_name "${A[1]}"
    case "${A[2]}" in on) run virsh autostart -- "${A[1]}";; off) run virsh autostart --disable -- "${A[1]}";; *) deny "use on or off";; esac;;
  smart-test-short) argc 2; v_dev "${A[1]}"; tier_change; run smartctl -t short "${A[1]}";;
  smart-test-long)  argc 2; v_dev "${A[1]}"; tier_change; run smartctl -t long "${A[1]}";;
  zpool-scrub) argc 2; v_zpool "${A[1]}"; tier_change; run zpool scrub "${A[1]}";;
  btrfs-scrub) argc 2; v_btrfs_pool "${A[1]}"; tier_change; run btrfs scrub start "/mnt/${A[1]}";;
  mover-start) argc 1; tier_change; run mover start;;
  parity-check)  argc 1; enabled "$ENABLE_PARITY"; tier_change; run mdcmd check NOCORRECT;;
  parity-cancel) argc 1; enabled "$ENABLE_PARITY"; tier_change; run mdcmd nocheck;;
  share-set)
    argc 4; v_name "${A[1]}"; v_key "${A[2]}"; v_value "${A[3]}"
    if   [[ "$SAFE_SHARE_KEYS" == *" ${A[2]} "* ]]; then tier_change
    elif [[ "$SENSITIVE_SHARE_KEYS" == *" ${A[2]} "* ]]; then tier_dangerous
    else deny "'${A[2]}' is not a recognised share setting (safe:$SAFE_SHARE_KEYS| sensitive:$SENSITIVE_SHARE_KEYS)"; fi
    set_kv "$CONFIG_ROOT/shares/${A[1]}.cfg" "${A[2]}" "${A[3]}";;
  cfg-restore)
    argc 2
    [[ "${A[1]}" =~ ^[A-Za-z0-9_.-]{1,120}\.cfg\.[0-9]{8}-[0-9]{6}$ ]] || deny "backup name must look like shares__appdata.cfg.20261023-101500 (see cfg-backups)"
    SRC="$BACKUP_DIR/${A[1]}"; ID="${A[1]%.*}"; REL="${ID//__//}"
    [[ "$REL" =~ ^(shares/)?[A-Za-z0-9_.-]+\.cfg$ ]] || deny "backup does not map to a config file"
    DST="$CONFIG_ROOT/$REL"
    if [[ "$REL" == shares/* ]]; then tier_change; else tier_dangerous; fi
    if [ "$DRYRUN" = "1" ]; then allow_log; echo "DRYRUN: restore $SRC -> $DST"; exit 0; fi
    [ -f "$SRC" ] || deny "no such backup: ${A[1]}"
    allow_log
    if [ -f "$DST" ]; then B="$(backup_file "$DST")"; else B="(none)"; fi
    cp -p -- "$SRC" "$DST" || deny "restore failed"
    log "RESTORED: $DST from ${A[1]} (previous saved as $B)"
    echo "restored $DST from ${A[1]} (previous version saved as $B)"; exit 0;;

  # =========================== DANGEROUS ===========================
  docker-remove)      argc 2; v_name "${A[1]}"; tier_dangerous; run docker rm -- "${A[1]}";;   # stopped containers only; appdata & template kept
  docker-image-prune) argc 1; tier_dangerous; run docker image prune -f;;                     # dangling images only
  vm-force-stop)      argc 2; v_name "${A[1]}"; tier_dangerous; run virsh destroy -- "${A[1]}";;  # hard power-off of the VM; VM is NOT deleted
  cfg-set)
    argc 4
    [[ "${A[1]}" =~ ^[A-Za-z0-9_-]{1,64}\.cfg$ ]] || deny "cfg-set takes a top-level file name like ident.cfg"
    v_key "${A[2]}"; v_value "${A[3]}"; tier_dangerous
    set_kv "$CONFIG_ROOT/${A[1]}" "${A[2]}" "${A[3]}";;
  parity-check-correct) argc 1; enabled "$ENABLE_PARITY"; tier_dangerous; run mdcmd check CORRECT;;
  plugin-install)
    argc 2; enabled "$ENABLE_PLUGINS"
    [[ "${A[1]}" =~ ^https://[A-Za-z0-9.-]+/[A-Za-z0-9._/~:-]+\.plg$ ]] || deny "plugin URL must be https://.../name.plg"
    tier_dangerous; run plugin install "${A[1]}";;
  plugin-update|plugin-remove)
    argc 2; enabled "$ENABLE_PLUGINS"
    [[ "${A[1]}" =~ ^[A-Za-z0-9._-]{1,80}\.plg$ ]] || deny "plugin name must look like name.plg"
    tier_dangerous; run plugin "${CMD#plugin-}" "${A[1]}";;
  server-restart)  argc 1; enabled "$ENABLE_POWER"; tier_dangerous; run powerdown -r;;
  server-poweroff) argc 1; enabled "$ENABLE_POWER"; tier_dangerous; run powerdown;;

  *) deny "unknown command '$CMD' (try 'help')";;
esac
