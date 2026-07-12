#!/usr/bin/env bash
# DKMS-based deploy of the bbr_e module (debian_bbr_v3/) to a server.
#
# Unlike deploy.sh (one-shot build against the running kernel; the ko dies on
# the next kernel upgrade), this installs the source as a DKMS package with
# AUTOINSTALL=yes, so the module is rebuilt automatically for every new
# kernel, plus boot persistence (modules-load.d + sysctl drop-in).
#
#   ./deploy_dkms.sh [user@host[:port]]
#
# Default target: the `ssh:` line of doc/testserver.md (server1).
# What it does on the server:
#   1. apt-get install dkms + headers for the running kernel (if missing)
#   2. sync source to /usr/src/tcp-bbr-e-<ver>/, dkms add/build/install
#   3. remove stale non-DKMS installs of our module (extra/tcp_bbr_e.ko),
#      warn about any OTHER tcp-cc DKMS packages (never auto-removes them)
#   4. persistence: /etc/modules-load.d/tcp_bbr_e.conf +
#      /etc/sysctl.d/90-bbr-e.conf, and warns about later-sorted sysctl files
#      that would override the default cc with a different value
#   5. swap the running module (detached remote script, reload.sh-style: park
#      cc on stock bbr, drain nginx/iperf3, rmmod retries). If the old module
#      stays pinned by live sockets the swap is skipped WITHOUT failing —
#      the DKMS install is complete and the new build takes over on reboot.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_DIR="$REPO_ROOT/debian_bbr_v3"
TESTSERVER_DOC="$REPO_ROOT/doc/testserver.md"
PKG=tcp-bbr-e
MODULE=tcp_bbr_e
REMOTE_LOG=/var/log/deploy_tcp_bbr_dkms.log

for f in tcp_bbr.c Makefile dkms.conf; do
  [ -f "$SRC_DIR/$f" ] || { echo "missing $SRC_DIR/$f" >&2; exit 1; }
done

VER=$(sed -n 's/^PACKAGE_VERSION="\(.*\)"/\1/p' "$SRC_DIR/dkms.conf")
[ -n "$VER" ] || { echo "could not parse PACKAGE_VERSION from dkms.conf" >&2; exit 1; }

if [ -n "${1:-}" ]; then
  TARGET="$1"
elif [ -f "$TESTSERVER_DOC" ]; then
  TARGET=$(awk -F': ' '/^ssh:/{print $2; exit}' "$TESTSERVER_DOC")
else
  TARGET=""
fi
[ -n "$TARGET" ] || { echo "no target given and none parsed from $TESTSERVER_DOC; usage: deploy_dkms.sh user@host[:port]" >&2; exit 1; }
USER_HOST="${TARGET%%:*}"
PORT="${TARGET##*:}"
[ "$PORT" = "$TARGET" ] && PORT=22

SSH=(ssh -p "$PORT" -o ConnectTimeout=10 "$USER_HOST")
echo "==> target: $USER_HOST:$PORT   package: $PKG/$VER"

echo "[1/6] preflight: dkms + kernel headers"
"${SSH[@]}" '
  set -e
  export DEBIAN_FRONTEND=noninteractive
  command -v dkms >/dev/null || apt-get install -y dkms
  dpkg -s "linux-headers-$(uname -r)" >/dev/null 2>&1 || \
      apt-get install -y "linux-headers-$(uname -r)"
  echo "dkms $(dkms --version 2>/dev/null | head -1), kernel $(uname -r)"
'

echo "[2/6] syncing source to /usr/src/$PKG-$VER/"
"${SSH[@]}" "mkdir -p /usr/src/$PKG-$VER"
rsync -az -e "ssh -p $PORT" \
  "$SRC_DIR/tcp_bbr.c" "$SRC_DIR/Makefile" "$SRC_DIR/dkms.conf" \
  "$USER_HOST:/usr/src/$PKG-$VER/"

echo "[3/6] dkms add/build/install (running kernel; AUTOINSTALL covers future ones)"
"${SSH[@]}" "
  set -e
  # re-adding the same version after a source update requires a remove first
  dkms status | grep -q '^$PKG/$VER' && dkms remove $PKG/$VER --all || true
  dkms add $PKG/$VER
  dkms build $PKG/$VER
  dkms install $PKG/$VER
  dkms status | grep '^$PKG/'
"

echo "[4/6] cleaning stale non-DKMS installs; checking for foreign cc dkms packages"
"${SSH[@]}" "
  removed=0
  for ko in /lib/modules/*/extra/$MODULE.ko; do
    [ -e \"\$ko\" ] || continue
    echo \"removing stale non-DKMS install: \$ko\"
    rm -f \"\$ko\"; removed=1
  done
  [ \"\$removed\" = 1 ] && depmod -a
  foreign=\$(dkms status 2>/dev/null | grep -i 'tcp' | grep -v '^$PKG/' || true)
  if [ -n \"\$foreign\" ]; then
    echo 'WARNING: other tcp-related DKMS packages present (NOT touched):'
    echo \"\$foreign\"
    echo 'If one of them shadows the in-kernel tcp_bbr, stock-bbr baselines are invalid.'
  fi
  # in-kernel bbr must resolve inside the kernel tree (no shadowing)
  modinfo -F filename tcp_bbr | grep -q '/kernel/net/ipv4/' \
    && echo 'stock tcp_bbr: clean (kernel/net/ipv4)' \
    || echo 'WARNING: stock tcp_bbr is SHADOWED -- fix before benchmarking'
"

echo "[5/6] boot persistence (modules-load.d + sysctl drop-in)"
"${SSH[@]}" "
  set -e
  echo $MODULE > /etc/modules-load.d/$MODULE.conf
  printf 'net.ipv4.tcp_congestion_control = bbr_e\n' > /etc/sysctl.d/90-bbr-e.conf
  # anything sorting after 90-bbr-e.conf (or sysctl.conf, applied last) that
  # sets a DIFFERENT cc would override our default at boot
  conflicts=\$(grep -ls 'tcp_congestion_control' /etc/sysctl.conf /etc/sysctl.d/*.conf 2>/dev/null \
               | grep -v 90-bbr-e.conf || true)
  for f in \$conflicts; do
    val=\$(sed -n 's/.*tcp_congestion_control[ =]*//p' \"\$f\" | tail -1)
    if [ \"\$val\" != bbr_e ]; then
      echo \"WARNING: \$f sets tcp_congestion_control=\$val and may override bbr_e at boot\"
    fi
  done
"

echo "[6/6] swapping the running module (detached; skipped without failing if pinned)"
"${SSH[@]}" "cat > /tmp/bbr_e_dkms_swap.sh" <<'EOF'
#!/bin/bash
# Runs detached on the server so a dropped ssh session cannot orphan the swap.
set -u
MODULE=tcp_bbr_e
LOG="${1:-/var/log/deploy_tcp_bbr_dkms.log}"
exec >>"$LOG" 2>&1
echo "=== dkms swap start $(date -Is) ==="

new_src=$(modinfo -F srcversion "$MODULE" 2>/dev/null)
cur_src=$(cat /sys/module/$MODULE/srcversion 2>/dev/null)
echo "installed srcversion: ${new_src:-none}  loaded: ${cur_src:-not loaded}"

if [ -n "$cur_src" ] && [ "$cur_src" != "$new_src" ]; then
    echo "parking default cc on stock bbr and draining consumers"
    sysctl -w net.ipv4.tcp_congestion_control=bbr || \
        sysctl -w net.ipv4.tcp_congestion_control=cubic
    systemctl stop nginx 2>/dev/null
    systemctl stop iperf3 2>/dev/null || pkill -f 'iperf3 -s' 2>/dev/null
    unloaded=0
    for i in $(seq 1 30); do
        if rmmod "$MODULE" 2>>"$LOG"; then unloaded=1; break; fi
        sleep 2
    done
    if [ "$unloaded" != 1 ]; then
        echo "old module still pinned by live sockets; NEW build takes over on next boot"
        systemctl start nginx 2>/dev/null
        systemctl start iperf3 2>/dev/null
        sysctl -w net.ipv4.tcp_congestion_control=bbr_e
        echo "=== dkms swap SKIPPED-PINNED $(date -Is) ==="
        exit 0
    fi
fi

modprobe "$MODULE" || { echo "modprobe failed"; echo "=== dkms swap FAILED $(date -Is) ==="; exit 1; }
sysctl -w net.ipv4.tcp_congestion_control=bbr_e
systemctl start nginx 2>/dev/null
systemctl start iperf3 2>/dev/null
echo "loaded srcversion now: $(cat /sys/module/$MODULE/srcversion)"
echo "=== dkms swap DONE $(date -Is) ==="
EOF
"${SSH[@]}" "chmod +x /tmp/bbr_e_dkms_swap.sh; rm -f $REMOTE_LOG; nohup /tmp/bbr_e_dkms_swap.sh $REMOTE_LOG >/dev/null 2>&1 & disown; echo kicked off"

status=""
for i in $(seq 1 30); do
  sleep 3
  if "${SSH[@]}" "grep -qE '=== dkms swap (DONE|SKIPPED-PINNED)' $REMOTE_LOG" 2>/dev/null; then
    status=ok; break
  fi
  if "${SSH[@]}" "grep -q '=== dkms swap FAILED' $REMOTE_LOG" 2>/dev/null; then
    status=failed; break
  fi
  echo "    ... waiting for swap ($i/30)"
done
"${SSH[@]}" "tail -n 20 $REMOTE_LOG" || true
[ "$status" = failed ] && exit 1
[ -z "$status" ] && { echo "TIMEOUT waiting for swap; check $REMOTE_LOG on the server" >&2; exit 1; }

echo "==> verify"
"${SSH[@]}" "
  dkms status | grep '^$PKG/'
  lsmod | grep -w $MODULE
  echo \"loaded srcversion: \$(cat /sys/module/$MODULE/srcversion 2>/dev/null)\"
  echo \"on-disk srcversion: \$(modinfo -F srcversion $MODULE)\"
  echo \"module path: \$(modinfo -F filename $MODULE)\"
  sysctl net.ipv4.tcp_congestion_control
"
echo "done."
