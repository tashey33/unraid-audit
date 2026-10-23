#!/bin/bash
# =============================================================================
# approve.sh — OWNER-ONLY approval helper for claude-gate DANGEROUS commands.
#
# Run it from YOUR OWN root session (WebGUI terminal, or SSH with your normal
# key) — never through the audit key (the gate has no command that runs it).
#
#   bash /boot/config/claude-gate/approve.sh docker-remove plex   # approve one exact request
#   bash /boot/config/claude-gate/approve.sh --list               # show pending approvals
#   bash /boot/config/claude-gate/approve.sh --revoke-all         # cancel all pending approvals
#
# An approval is valid for ONE use of exactly that request (same command and
# arguments) and expires after APPROVAL_TTL_MIN minutes (set in gate.sh).
# =============================================================================
set -u
DIR="${GATE_APPROVAL_DIR:-/boot/config/claude-gate/approvals}"

if [ -n "${SSH_ORIGINAL_COMMAND:-}" ]; then
  echo "approve.sh must be run by the owner, not through a forced-command key" >&2; exit 1
fi
[ $# -ge 1 ] || { sed -n '2,16p' "$0"; exit 1; }
mkdir -p -- "$DIR"

case "$1" in
  --list)
    shopt -s nullglob; files=("$DIR"/*)
    [ ${#files[@]} -eq 0 ] && { echo "no pending approvals"; exit 0; }
    for f in "${files[@]}"; do echo "$(date -r "$f" '+%F %T')  $(head -n1 "$f")"; done; exit 0;;
  --revoke-all)
    rm -f -- "$DIR"/*; logger -t claude-gate "APPROVALS-REVOKED" 2>/dev/null; echo "all pending approvals revoked"; exit 0;;
esac

read -r -a A <<< "$*"
NREQ="${A[*]}"
case "$NREQ" in *[!A-Za-z0-9\ ._:/=,~-]*) echo "request contains characters the gate would refuse" >&2; exit 1;; esac

echo "You are approving ONE run of this DANGEROUS request:"
echo "    $NREQ"
read -r -p "Type YES to approve: " ans
[ "$ans" = "YES" ] || { echo "not approved"; exit 1; }

h="$(printf '%s' "$NREQ" | sha256sum | cut -d' ' -f1)"
printf '%s | approved %s by %s\n' "$NREQ" "$(date -Is)" "${SUDO_USER:-${USER:-root}}" > "$DIR/$h"
logger -t claude-gate "APPROVAL-CREATED: [$NREQ]" 2>/dev/null
echo "Approved for one use within the gate's time limit: $NREQ"
